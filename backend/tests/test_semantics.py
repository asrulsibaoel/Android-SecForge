from dataclasses import dataclass

from app.analysis.reachability import build_code_graph, find_paths
from app.analysis.semantics import augment_graph, semantic_findings


@dataclass
class _Binding:
    source: str
    confidence: str
    java_class: str = None
    java_method: str = None
    library_name: str = None
    native_function: str = None
    evidence: str = ""


def _comp(name, kind="activity", ifs=None):
    return {"name": name, "type": kind, "effective_exported": True, "permission": None, "intent_filters": ifs or []}


def _analyze(src, comps, native=None, jni=None):
    graph = build_code_graph(src, native or [], jni or [], comps)
    augment_graph(graph, comps, jni or [], native or [])
    return graph, semantic_findings(graph)


def _ids(findings):
    return {f.rule_id for f in findings}


def test_case1_exported_activity_receives_input():
    src = [("p/A1.java", 'package p;\nclass A1 { public void onCreate(){ String s=getIntent().getStringExtra("x"); load(s);} void load(String s){ Class.forName(s);} }')]
    graph, findings = _analyze(src, [_comp(".A1")])
    assert "ANDROID-SEMANTIC-001" in _ids(findings)
    # framework dispatch edge exists to onCreate
    assert any(e.edge_type == "FRAMEWORK_DISPATCH" for e in graph.semantic_edges)


def test_case2_deep_link_reachability():
    ifs = [{"actions": ["android.intent.action.VIEW"], "categories": ["android.intent.category.BROWSABLE"],
            "data": [{"scheme": "https", "host": "example.com", "path": "/doc"}]}]
    src = [("p/DL.java", 'package p;\nclass DL { public void onCreate(){ String id=getIntent().getData().getQueryParameter("id"); web.loadUrl(id);} }')]
    graph, findings = _analyze(src, [_comp(".DL", ifs=ifs)])
    assert len(graph.deep_links) == 1
    assert graph.deep_links[0]["scheme"] == "https"
    assert any(e.edge_type == "DEEP_LINK" for e in graph.semantic_edges)


def test_case3_exported_receiver_receives_intent():
    src = [("p/Rcv.java", 'package p;\nclass Rcv { public void onReceive(Object c, Object i){ String s=i.getStringExtra("x"); } }')]
    graph, findings = _analyze(src, [_comp(".Rcv", "receiver")])
    assert "ANDROID-SEMANTIC-001" in _ids(findings)
    assert any(ep["lifecycle_event"] == "RECEIVE" for ep in graph.android_entry_points)


def test_case4_provider_reaches_file_operation():
    src = [("p/Prov.java", 'package p;\nclass Prov { public Object query(Object uri, Object proj){ new FileOutputStream("/tmp/x"); return null; } }')]
    graph, findings = _analyze(src, [_comp(".Prov", "provider")])
    assert any(s["type"] == "content_provider_input" for s in graph.sources)
    assert "ANDROID-SEMANTIC-002" in _ids(findings)


def test_case5_binder_service_entry():
    src = [("p/Svc.java", 'package p;\nclass Svc { public boolean onTransact(int code, Object data, Object reply, int flags){ switch(code){ case 1: Runtime.getRuntime().exec("x"); } return true; } }')]
    graph, findings = _analyze(src, [_comp(".Svc", "service")])
    assert any(t["kind"] == "SERVICE_ENTRY" for t in graph.ipc_transactions)
    assert "ANDROID-SEMANTIC-003" in _ids(findings)


def test_case6_webview_javascript_interface():
    src = [("p/W.java", 'package p;\nclass W { void onCreate(){ web.addJavascriptInterface(new B(), "androidBridge"); } }')]
    graph, findings = _analyze(src, [_comp(".W")])
    assert "ANDROID-SEMANTIC-004" in _ids(findings)
    assert any(e.edge_type == "WEBVIEW_BRIDGE" for e in graph.semantic_edges)


def test_case7_reflection_constant_no_finding():
    src = [("p/R.java", 'package p;\nclass R { void onCreate(){ Class.forName("com.example.Target"); } }')]
    graph, findings = _analyze(src, [_comp(".R")])
    assert "ANDROID-SEMANTIC-005" not in _ids(findings)
    assert any(e.edge_type == "REFLECTION_TARGET" for e in graph.semantic_edges)


def test_case8_dynamic_load_constant_no_finding():
    src = [("p/D.java", 'package p;\nclass D { void onCreate(){ new DexClassLoader("/data/x.dex", null, null, null); } }')]
    graph, findings = _analyze(src, [_comp(".D")])
    assert "ANDROID-SEMANTIC-005" not in _ids(findings)  # constant path, no external input
    assert any(e.edge_type == "DYNAMIC_LOAD" for e in graph.semantic_edges)


def test_case8b_dynamic_load_from_external_input():
    src = [("p/D2.java", 'package p;\nclass D2 { void onCreate(){ String p=getIntent().getStringExtra("p"); new DexClassLoader(p, null, null, null); } }')]
    graph, findings = _analyze(src, [_comp(".D2")])
    assert "ANDROID-SEMANTIC-005" in _ids(findings)


def test_case9_disconnected_source_and_sink():
    src = [
        ("p/S9.java", 'package p;\nclass S9 { void onCreate(){ String u=getIntent().getStringExtra("u"); log(u);} void log(String s){} }'),
        ("p/K9.java", 'package p;\nclass K9 { void other(){ Runtime.getRuntime().exec("id"); } }'),
    ]
    graph, findings = _analyze(src, [_comp(".S9")])
    # no path connects the source to the unrelated exec sink
    source_node = next(k for k, n in graph.nodes.items() if n.node_type == "SOURCE")
    exec_sink = next(k for k, n in graph.nodes.items() if n.node_type == "SECURITY_SINK" and n.extra.get("sink_type") == "command_exec")
    assert find_paths(graph, source_node, exec_sink, max_depth=20) == []
    # and no source->sink semantic/reachability finding was produced
    assert "ANDROID-SEMANTIC-002" not in _ids(findings)
    assert "ANDROID-SEMANTIC-005" not in _ids(findings)


def test_confidence_not_upgraded_for_low_jni():
    src = [("p/C.java", 'package p;\nclass C { public native void n(String s); void onCreate(){ String u=getIntent().getStringExtra("x"); n(u);} }')]
    jni = [_Binding("ELF_EXPORT", "LOW", "p.C", "n", "libn.so", "Java_p_C_n")]
    graph, findings = _analyze(src, [_comp(".C")], jni=jni)
    boundary = [b for b in graph.security_boundaries if b["boundary_type"] == "JNI"]
    assert boundary and boundary[0]["confidence"] == "LOW"


def test_intent_operation_extraction():
    src = [("p/I.java", 'package p;\nclass I { void go(){ Intent x = new Intent("android.intent.action.VIEW"); startActivity(x); } }')]
    graph, findings = _analyze(src, [_comp(".I")])
    ops = {i["operation"] for i in graph.intents}
    assert "new Intent" in ops
    assert any(i["action"] == "android.intent.action.VIEW" for i in graph.intents)
