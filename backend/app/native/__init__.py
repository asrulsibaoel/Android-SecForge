"""Deep native / Ghidra correlation (prompt 20).

Supplements — never replaces — existing ELF/JNI native evidence with deeper
static native analysis (optionally from Ghidra). Ghidra is optional; offline
ELF-only operation remains fully functional. All external execution is confined
to the controlled adapter boundary (argument arrays, timeouts, output caps — no
arbitrary command strings). This is static analysis only; no exploitation, and
no `exploitable` conclusion is ever produced.
"""
