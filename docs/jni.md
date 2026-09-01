# JNI analysis

JNI discovery (`backend/app/analysis/jni.py`) connects Java/Kotlin to native
code using only statically-observable evidence.

## Sides observed

**ELF side** — exported symbols named `Java_<pkg>_<Class>_<method>` are demangled
per the JNI specification, including the escape rules:

| Escape | Meaning |
| --- | --- |
| `_1` | literal `_` |
| `_2` | `;` |
| `_3` | `[` |
| `_0XXXX` | Unicode code point `U+XXXX` |
| `_` (otherwise) | package/class separator |

An overloaded method's `__<signature>` suffix is stripped. `JNI_OnLoad` exports
are recorded as a signal that dynamic registration (`RegisterNatives`) may be in
use — which cannot be resolved from symbols alone.

**Java side** — decompiled sources (from JADX, when available) are scanned for
`native` method declarations and for `System.loadLibrary` / `System.load` /
`Runtime...loadLibrary` calls.

## Bindings and confidence

Each `JNIBinding` records a `source` (`ELF_EXPORT`, `JAVA_NATIVE`, `JNI_ONLOAD`,
`LOAD_LIBRARY`), a `confidence`, and explicit `evidence`:

- **HIGH** — an ELF `Java_*` export whose demangled class+method matches a
  declared Java `native` method (both sides observed); or a `loadLibrary("x")`
  where `libx.so` is present.
- **MEDIUM** — an ELF `Java_*` export or `JNI_OnLoad` with no confirmed Java side
  (e.g. the DEX was not decompiled).
- **LOW** — a Java `native` method with no matching ELF export (dynamic
  registration, or the implementing library absent).

A mapping is never claimed when it cannot be shown. When JADX is unavailable,
bindings derive from the ELF side only and are reported at MEDIUM confidence.

## JNI security surface

Bindings capture the Java entry point, native library, native function, and (when
available) the Java signature — the relationships needed to reason about which
native functions are reachable from Java. Advanced taint analysis is out of scope
for this milestone; only explicit static relationships are recorded.
