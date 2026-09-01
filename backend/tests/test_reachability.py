from dataclasses import dataclass, field

from app.analysis.reachability import (
    build_code_graph,
    find_paths,
    parse_java,
    reachability_findings,
    reachability_paths,
    N_SINK,
    N_SOURCE,
)


@dataclass
class _Func:
    name: str
    kind: str
    is_jni: bool = False


@dataclass
class _Lib:
    filename: str
    abi: str = "arm64-v8a"
    architecture: str = "aarch64"
    status: str = "COMPLETE"
    functions: list = field(default_factory=list)


@dataclass
class _Binding:
    source: str
    confidence: str
    java_class: str = None
    java_method: str = None
    library_name: str = None
    native_function: str = None
    evidence: str = ""


def _comp(name, kind="activity"):
    return {"name": name, "type": kind, "effective_exported": True, "permission": None, "intent_filters": []}


def _graph(src, native=None, jni=None, comps=None):
    return build_code_graph(src, native or [], jni or [], comps or [])


# ---- parsing / call graph ----

def test_parse_java_extracts_methods_and_native():
    src = "package p;\nclass Foo {\n void a() {}\n public native int b(String s);\n}"
    methods = parse_java("Foo.java", src)
    names = {m.name: m for m in methods}
    assert "a" in names and "b" in names
    assert names["b"].is_native is True
    assert names["a"].fqcn == "p.Foo"


def test_call_graph_same_class_resolution():
    src = [("p/Foo.java", "package p;\nclass Foo {\n void onCreate(){ helper(); }\n void helper(){ }\n}")]
    graph = _graph(src, comps=[_comp(".Foo")])
    calls = [(e.src, e.dst) for e in graph.edges if e.edge_type == "CALLS"]
    assert any(s.endswith("Foo#onCreate") and d.endswith("Foo#helper") for s, d in calls)


# ---- source / sink detection ----

def test_source_detection():
    src = [("p/A.java", 'package p;\nclass A { void onCreate(){ String u = getIntent().getStringExtra("u"); } }')]
    graph = _graph(src, comps=[_comp(".A")])
    assert any(s["api"] == "Intent.getStringExtra" for s in graph.sources)


def test_sink_detection_java_and_native():
    src = [("p/A.java", 'package p;\nclass A { void f(){ web.loadUrl("x"); } }')]
    native = [_Lib("libx.so", functions=[_Func("strcpy", "imported")])]
    graph = _graph(src, native=native, comps=[])
    apis = {s["api"] for s in graph.sinks}
    assert "WebView.loadUrl" in apis
    assert "strcpy" in apis  # native sink from imported symbol


# ---- CASE 1..5 (deterministic) ----

def test_case1_harmless_no_finding():
    src = [("p/C1.java", 'package p;\nclass C1 { void onCreate(){ String u=getIntent().getStringExtra("u"); harmless(u);} void harmless(String s){int n=s.length();} }')]
    findings = reachability_findings(reachability_paths(_graph(src, comps=[_comp(".C1")])))
    assert findings == []


def test_case2_intent_to_webview():
    src = [("p/C2.java", 'package p;\nclass C2 { void onCreate(){ String u=getIntent().getStringExtra("url"); web.loadUrl(u);} }')]
    findings = reachability_findings(reachability_paths(_graph(src, comps=[_comp(".C2")])))
    assert any(f.rule_id == "ANDROID-REACH-001" and f.status == "REACHABLE" for f in findings)


def test_case3_component_to_jni_boundary():
    src = [("p/C3.java", 'package p;\nclass C3 { void onCreate(){ String u=getIntent().getStringExtra("x"); process(u);} void process(String s){ nativeVerify(s);} public native int nativeVerify(String s); }')]
    native = [_Lib("libn.so", functions=[_Func("Java_p_C3_nativeVerify", "exported", True), _Func("strcpy", "imported")])]
    jni = [_Binding("ELF_EXPORT", "HIGH", "p.C3", "nativeVerify", "libn.so", "Java_p_C3_nativeVerify")]
    findings = reachability_findings(reachability_paths(_graph(src, native=native, jni=jni, comps=[_comp(".C3")])))
    reach003 = [f for f in findings if f.rule_id == "ANDROID-REACH-003"]
    assert reach003 and reach003[0].status == "REACHABLE"
    # evidence chain crosses the JNI boundary and stops at the native function (no fabricated native call graph)
    labels = [e.detail for e in reach003[0].evidence]
    assert any("JNI_BINDING" in d for d in labels)
    assert any("NATIVE_FUNCTION" in d for d in labels)


def test_case4_intent_to_processbuilder():
    src = [("p/C4.java", 'package p;\nclass C4 { void onCreate(){ String c=getIntent().getStringExtra("cmd"); new ProcessBuilder(c).start();} }')]
    findings = reachability_findings(reachability_paths(_graph(src, comps=[_comp(".C4")])))
    assert any(f.rule_id == "ANDROID-REACH-002" for f in findings)


def test_case5_unrelated_source_and_sink_not_connected():
    src = [
        ("p/A5.java", 'package p;\nclass A5 { void onCreate(){ String u=getIntent().getStringExtra("u"); log(u);} void log(String s){} }'),
        ("p/B5.java", 'package p;\nclass B5 { void unrelated(){ web.loadUrl("http://x"); } }'),
    ]
    graph = _graph(src, comps=[_comp(".A5")])
    # both a source and a sink exist...
    assert graph.sources and graph.sinks
    # ...but there is no path connecting them, and no finding is produced
    assert reachability_findings(reachability_paths(graph)) == []


# ---- confidence + bounded traversal ----

def test_confidence_propagates_from_weakest_edge():
    # LOW-confidence JNI binding should cap the path confidence at LOW.
    src = [("p/C.java", 'package p;\nclass C { void onCreate(){ String u=getIntent().getStringExtra("x"); n(u);} public native void n(String s); }')]
    native = [_Lib("libn.so", functions=[_Func("Java_p_C_n", "exported", True)])]
    jni = [_Binding("JAVA_NATIVE", "LOW", "p.C", "n", "libn.so", "Java_p_C_n")]
    findings = reachability_findings(reachability_paths(_graph(src, native=native, jni=jni, comps=[_comp(".C")])))
    reach = [f for f in findings if f.rule_id == "ANDROID-REACH-003"]
    assert reach and reach[0].confidence == "LOW"


def test_bounded_traversal_respects_max_depth():
    src = [("p/C2.java", 'package p;\nclass C2 { void onCreate(){ String u=getIntent().getStringExtra("url"); web.loadUrl(u);} }')]
    graph = _graph(src, comps=[_comp(".C2")])
    entry = next(k for k, n in graph.nodes.items() if n.node_type == "ENTRY_POINT")
    sink = next(k for k, n in graph.nodes.items() if n.node_type == N_SINK)
    assert find_paths(graph, entry, sink, max_depth=1) == []  # too shallow
    assert find_paths(graph, entry, sink, max_depth=10)  # reachable within bound
