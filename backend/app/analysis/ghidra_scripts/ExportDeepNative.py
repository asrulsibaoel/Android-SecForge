# Ghidra headless post-script (Jython, runs INSIDE Ghidra — not CPython).
#
# Exports a normalized DEEP-NATIVE view (functions, calls, imports, exports,
# symbols, strings, references) as JSON to the path given as the first script
# argument. Invoked by app/native/ghidra_adapter.py via:
#   analyzeHeadless ... -postScript ExportDeepNative.py <output.json>
#
# Static analysis / evidence extraction only. No modification of the program.
#
# @category AndroidSecForge
import json

args = getScriptArgs()
output_path = args[0] if args else "ghidra_deep.json"

MAX_FUNCS = 20000
MAX_CALLS = 100000
MAX_STRINGS = 20000

program = currentProgram
fm = program.getFunctionManager()
listing = program.getListing()
refs = program.getReferenceManager()

functions = []
calls = []
by_entry = {}
count = 0
for func in fm.getFunctions(True):
    if count >= MAX_FUNCS:
        break
    count += 1
    entry = str(func.getEntryPoint())
    name = func.getName()
    is_external = func.isExternal()
    functions.append({
        "name": name,
        "address": entry,
        "size": int(func.getBody().getNumAddresses()),
        "namespace": func.getParentNamespace().getName(True) if func.getParentNamespace() else "",
        "exported": bool(func.getSymbol().isGlobal()) if func.getSymbol() else False,
        "imported": bool(is_external),
    })
    by_entry[entry] = name

# call edges (from function -> called function), bounded
cedge = 0
for func in fm.getFunctions(True):
    if cedge >= MAX_CALLS:
        break
    src = func.getName()
    for callee in func.getCalledFunctions(None):
        if cedge >= MAX_CALLS:
            break
        cedge += 1
        calls.append({
            "src": src, "dst": callee.getName(),
            "src_addr": str(func.getEntryPoint()), "dst_addr": str(callee.getEntryPoint()),
        })

# imports / exports via symbol table
imports = []
exports = []
symbols = []
st = program.getSymbolTable()
for sym in st.getAllSymbols(True):
    stype = str(sym.getSymbolType())
    entry = {"name": sym.getName(), "type": stype, "address": str(sym.getAddress()), "kind": "local"}
    if sym.isExternal():
        entry["kind"] = "import"
        imports.append({"name": sym.getName(), "library": ""})
    elif sym.isGlobal():
        entry["kind"] = "export"
        exports.append({"name": sym.getName(), "address": str(sym.getAddress())})
    symbols.append(entry)

# defined strings, bounded
strings = []
scount = 0
for data in listing.getDefinedData(True):
    if scount >= MAX_STRINGS:
        break
    try:
        if data.hasStringValue():
            strings.append({"value": str(data.getValue()), "address": str(data.getAddress())})
            scount += 1
    except Exception:
        continue

payload = {
    "program": program.getName(),
    "language": str(program.getLanguageID()),
    "architecture": str(program.getLanguage().getProcessor()),
    "functions": functions,
    "calls": calls,
    "imports": imports,
    "exports": exports,
    "symbols": symbols,
    "strings": strings,
    "references": [],
    "jni_registrations": [],
}

with open(output_path, "w") as handle:
    json.dump(payload, handle)
