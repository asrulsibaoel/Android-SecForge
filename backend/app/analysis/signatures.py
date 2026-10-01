"""Declarative source / sink signatures for the reachability engine.

Kept as data (separate from engine logic) so the catalogue is easy to review and
extend. Only APIs actually observed in decompiled code create Source/Sink nodes;
presence of a signature never, by itself, implies a vulnerability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Signature:
    id: str
    api: str
    kind: str  # source category or sink category
    pattern: str

    def regex(self) -> re.Pattern[str]:
        return re.compile(self.pattern)


# Potentially attacker-controlled input sources (Android IPC, web, network, provider).
SOURCE_SIGNATURES: tuple[Signature, ...] = (
    Signature("SRC-INTENT-STRING", "Intent.getStringExtra", "intent", r"\.getStringExtra\s*\("),
    Signature("SRC-INTENT-EXTRAS", "Intent.getExtras", "intent", r"\.getExtras\s*\("),
    Signature("SRC-INTENT-DATA", "Intent.getData", "intent", r"\.getData\s*\(\s*\)"),
    Signature("SRC-INTENT-DATASTRING", "Intent.getDataString", "intent", r"\.getDataString\s*\("),
    Signature("SRC-INTENT-PARCELABLE", "Intent.getParcelableExtra", "intent", r"\.getParcelableExtra\s*\("),
    Signature("SRC-INTENT-SERIALIZABLE", "Intent.getSerializableExtra", "intent", r"\.getSerializableExtra\s*\("),
    Signature("SRC-INTENT-INT", "Intent.getIntExtra", "intent", r"\.getIntExtra\s*\("),
    Signature("SRC-BUNDLE-STRING", "Bundle.getString", "bundle", r"\.getString\s*\("),
    Signature("SRC-BUNDLE-BYTES", "Bundle.getByteArray", "bundle", r"\.getByteArray\s*\("),
    Signature("SRC-BUNDLE-SERIALIZABLE", "Bundle.getSerializable", "bundle", r"\.getSerializable\s*\("),
    Signature("SRC-URI-QUERY", "Uri.getQueryParameter", "uri", r"\.getQueryParameter\s*\("),
    Signature("SRC-URI-PATH", "Uri.getPath", "uri", r"\.getPath\s*\(\s*\)"),
    Signature("SRC-URI-LASTSEG", "Uri.getLastPathSegment", "uri", r"\.getLastPathSegment\s*\("),
    Signature("SRC-NET-STREAM", "URLConnection.getInputStream", "network", r"\.getInputStream\s*\("),
    Signature("SRC-WEBVIEW-MESSAGE", "WebMessage", "webview", r"onReceiveValue\s*\("),
)

# Security-relevant Java sinks. These are SECURITY_RELEVANT_SINK, not vulnerabilities.
JAVA_SINK_SIGNATURES: tuple[Signature, ...] = (
    Signature("SINK-EXEC-RUNTIME", "Runtime.exec", "command_exec", r"\.exec\s*\("),
    Signature("SINK-EXEC-PROCESSBUILDER", "ProcessBuilder", "command_exec", r"new\s+ProcessBuilder\s*\("),
    Signature("SINK-WEBVIEW-LOADURL", "WebView.loadUrl", "webview", r"\.loadUrl\s*\("),
    Signature("SINK-WEBVIEW-EVAL", "WebView.evaluateJavascript", "webview", r"\.evaluateJavascript\s*\("),
    Signature("SINK-WEBVIEW-JSI", "WebView.addJavascriptInterface", "webview", r"\.addJavascriptInterface\s*\("),
    Signature("SINK-FILE-WRITE", "FileOutputStream.write", "file_write", r"new\s+FileOutputStream\s*\(|\.openFileOutput\s*\("),
    Signature("SINK-REFLECT-FORNAME", "Class.forName", "reflection", r"Class\.forName\s*\("),
    Signature("SINK-REFLECT-INVOKE", "Method.invoke", "reflection", r"\.invoke\s*\("),
    Signature("SINK-DEX-LOADER", "DexClassLoader", "dynamic_loading", r"new\s+(?:Dex|Path|InMemoryDex)ClassLoader\s*\("),
    Signature("SINK-SQL-RAW", "SQLiteDatabase.rawQuery", "sql", r"\.rawQuery\s*\(|\.execSQL\s*\("),
)

# Native security-relevant sink symbols (matched against a library's imports).
NATIVE_SINK_SYMBOLS: dict[str, str] = {
    "strcpy": "unsafe_string",
    "strcat": "unsafe_string",
    "sprintf": "unsafe_string",
    "vsprintf": "unsafe_string",
    "gets": "unsafe_string",
    "stpcpy": "unsafe_string",
    "scanf": "unsafe_parse",
    "sscanf": "unsafe_parse",
    "system": "command_exec",
    "popen": "command_exec",
    "execl": "command_exec",
    "execlp": "command_exec",
    "execv": "command_exec",
    "execvp": "command_exec",
}
