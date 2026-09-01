#!/usr/bin/env bash
# Launch the AndroidSecForge backend with the FULL analysis pipeline enabled:
#   - jadx  (DEX -> Java decompilation; feeds code_index / graph / reachability / semantics)
#   - Ghidra standalone stage (per-binary decompilation)
#   - Ghidra DEEP native (call-chain reachability over native libs)
#
# These are set here (the server's launch env) and DELIBERATELY NOT in backend/.env,
# because pytest reads .env from this directory — enabling Ghidra deep there would make
# the test suite invoke the real (slow) headless analyzer and break the hermetic
# `real .so -> ELF_ONLY` test. Tests stay fast/host-independent; the live server runs full.
#
# Trade-off: analyses are no longer instant. jadx adds ~10s; Ghidra deep adds roughly
# ~1 min per native library (Magisk's 24 libs ≈ 27 min). Run ONE native-heavy analysis
# at a time — a long Ghidra-deep run holds the SQLite write lock, so a concurrent
# analysis can hit "database is locked".
set -euo pipefail
cd "$(dirname "$0")"

export ASF_DATABASE_URL="sqlite:////tmp/claude-1000/-run-media-asrulsibaoel-Storage-personal-android-tester/2052eecc-91a8-4960-822b-b33f1aebaba8/scratchpad/accept25.db"
export ASF_JADX_PATH="/home/asrulsibaoel/tools/jadx/bin/jadx"
export ASF_GHIDRA_PATH="/home/asrulsibaoel/tools/ghidra_12.1.3_PUBLIC"
# ghidra_deep = the call-chain native intelligence ("Ghidra deep"): functions, call
# edges, JNI resolution, reachability. This is the one that matters — keep it ON.
export ASF_GHIDRA_DEEP_ENABLED="true"
# The legacy standalone `ghidra` stage (prompt8 per-library function extraction) is
# left OFF: it is redundant with ghidra_deep (which is strictly richer) AND its
# post-script is a `.py` GhidraScript that Ghidra 12 cannot run (Jython removed), so
# it would only ever complete with 0 functions. Set to "true" only if you also port
# app/analysis/ghidra_scripts/ExportFunctions.py to a .java GhidraScript.
export ASF_GHIDRA_ENABLED="false"

exec /usr/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --log-level info
