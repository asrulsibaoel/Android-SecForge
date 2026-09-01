"""Declarative, observation-only Frida hook profiles.

Hooks LOG calls and return values unchanged. They must never modify return
values, bypass security checks, disable TLS, inject commands, alter
authentication, dump credentials, bypass permissions, or patch memory. The Frida
script generated from these profiles calls each original implementation and
returns its result unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HookProfile:
    name: str
    category: str
    description: str
    java_targets: tuple[str, ...] = ()   # "class.method"
    native_targets: tuple[str, ...] = ()  # exported symbol names
    observation_only: bool = True


HOOK_PROFILES: tuple[HookProfile, ...] = (
    HookProfile("lifecycle", "lifecycle", "Activity lifecycle callbacks",
                ("android.app.Activity.onCreate", "android.app.Activity.onResume",
                 "android.app.Activity.onNewIntent")),
    HookProfile("intents", "intent", "Intent input accessors",
                ("android.content.Intent.getAction", "android.content.Intent.getData",
                 "android.content.Intent.getStringExtra", "android.net.Uri.getQueryParameter")),
    HookProfile("webview", "webview", "WebView load / bridge",
                ("android.webkit.WebView.loadUrl", "android.webkit.WebView.evaluateJavascript",
                 "android.webkit.WebView.addJavascriptInterface")),
    HookProfile("reflection", "reflection", "Reflection entry points",
                ("java.lang.Class.forName", "java.lang.reflect.Method.invoke")),
    HookProfile("dynamic_loading", "dynamic_loading", "Dynamic class loading",
                ("dalvik.system.DexClassLoader.$init", "dalvik.system.PathClassLoader.$init",
                 "java.lang.Runtime.loadLibrary", "java.lang.System.loadLibrary")),
    HookProfile("crypto", "crypto", "Cryptographic API usage",
                ("java.security.MessageDigest.getInstance", "javax.crypto.Cipher.getInstance",
                 "javax.crypto.Mac.getInstance")),
    HookProfile("network", "network", "Network / TLS APIs",
                ("java.net.URL.$init", "javax.net.ssl.SSLContext.init")),
    HookProfile("file_access", "file", "File I/O",
                ("java.io.FileInputStream.$init", "java.io.FileOutputStream.$init")),
    HookProfile("jni", "native", "JNI load boundary", (), ("JNI_OnLoad",)),
    HookProfile("native_dangerous", "native", "Dangerous native imports (observation only)",
                (), ("strcpy", "strcat", "system", "popen")),
)


def profiles_by_name(names: list[str]) -> list[HookProfile]:
    lookup = {p.name: p for p in HOOK_PROFILES}
    return [lookup[n] for n in names if n in lookup]


def build_frida_script(profiles: list[HookProfile], max_events: int) -> str:
    """Generate an observation-only Frida (JS) script for the given profiles.

    Each hook logs arguments (masked/truncated on the agent side is limited; the
    host also masks) and RETURNS THE ORIGINAL RESULT UNCHANGED.
    """
    java_targets = sorted({t for p in profiles for t in p.java_targets})
    native_targets = sorted({t for p in profiles for t in p.native_targets})
    lines = [
        "'use strict';",
        f"var __ASF_MAX = {max_events};",
        "var __asf_count = 0;",
        "function __asf_emit(o){ if(__asf_count++ >= __ASF_MAX){return;} send(o); }",
        "function __asf_arg(a){ try { var s = (a===null)?'null':(''+a); return s.length>200?s.substring(0,200)+'...':s; } catch(e){ return '<unprintable>'; } }",
        "Java.perform(function(){",
    ]
    for target in java_targets:
        cls, _, method = target.rpartition(".")
        lines.append(f"""  try {{
    var C = Java.use({cls!r});
    var overloads = C[{method!r}].overloads;
    overloads.forEach(function(ov){{
      ov.implementation = function(){{
        var args = [];
        for (var i=0;i<arguments.length;i++){{ args.push(__asf_arg(arguments[i])); }}
        var ret = ov.apply(this, arguments);            // call original, unchanged
        __asf_emit({{type:'JAVA', clazz:{cls!r}, method:{method!r}, args:args, ret:__asf_arg(ret)}});
        return ret;                                     // return unchanged
      }};
    }});
  }} catch(e) {{ /* class/method not present; observation only */ }}""")
    lines.append("});")
    for sym in native_targets:
        lines.append(f"""try {{
  var p = Module.findExportByName(null, {sym!r});
  if (p) {{
    Interceptor.attach(p, {{ onEnter: function(a){{ __asf_emit({{type:'NATIVE', symbol:{sym!r}}}); }} }});
  }}
}} catch(e) {{ }}""")
    return "\n".join(lines)
