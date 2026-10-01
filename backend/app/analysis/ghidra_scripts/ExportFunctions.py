# Ghidra headless post-script (Jython, runs INSIDE Ghidra — not CPython).
#
# Exports the analyzed program's functions as normalized JSON to the path given
# as the first script argument. Invoked by app/analysis/ghidra.py via
# analyzeHeadless -postScript ExportFunctions.py <output.json>.
#
# @category AndroidSecForge
import json

args = getScriptArgs()
output_path = args[0] if args else "ghidra_functions.json"

functions = []
fm = currentProgram.getFunctionManager()
for func in fm.getFunctions(True):
    functions.append({
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": int(func.getBody().getNumAddresses()),
        "namespace": func.getParentNamespace().getName(True) if func.getParentNamespace() else "",
    })

payload = {
    "program": currentProgram.getName(),
    "language": str(currentProgram.getLanguageID()),
    "function_count": len(functions),
    "functions": functions,
}

with open(output_path, "w") as handle:
    json.dump(payload, handle)
