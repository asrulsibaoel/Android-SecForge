// Ghidra headless post-script (Java GhidraScript — compiled/run by Ghidra itself,
// no Jython/PyGhidra needed; Ghidra 11/12 removed Jython).
//
// Exports a normalized DEEP-NATIVE view (functions, calls, imports, exports,
// symbols) as JSON to the path given as the first script argument. Invoked by
// app/native/ghidra_adapter.py via:
//   analyzeHeadless ... -postScript ExportDeepNative.java <output.json>
//
// Static analysis / evidence extraction only. No modification of the program.
//
// @category AndroidSecForge
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.FileWriter;
import java.io.Writer;
import java.util.Set;

public class ExportDeepNative extends GhidraScript {

    static final int MAX_FUNCS = 20000;
    static final int MAX_CALLS = 100000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args != null && args.length > 0) ? args[0] : "ghidra_deep.json";

        FunctionManager fm = currentProgram.getFunctionManager();

        // functions
        StringBuilder funcs = new StringBuilder("[");
        boolean first = true;
        int count = 0;
        FunctionIterator fit = fm.getFunctions(true);
        while (fit.hasNext() && count < MAX_FUNCS) {
            Function f = fit.next();
            count++;
            if (!first) funcs.append(",");
            first = false;
            Symbol s = f.getSymbol();
            boolean exported = (s != null) && s.isGlobal();
            String ns = (f.getParentNamespace() != null) ? f.getParentNamespace().getName(true) : "";
            funcs.append("{\"name\":").append(js(f.getName()))
                 .append(",\"address\":").append(js(f.getEntryPoint().toString()))
                 .append(",\"size\":").append(f.getBody().getNumAddresses())
                 .append(",\"namespace\":").append(js(ns))
                 .append(",\"exported\":").append(exported)
                 .append(",\"imported\":").append(f.isExternal())
                 .append("}");
        }
        funcs.append("]");

        // call edges (caller -> callee), bounded
        StringBuilder calls = new StringBuilder("[");
        first = true;
        int ce = 0;
        fit = fm.getFunctions(true);
        while (fit.hasNext() && ce < MAX_CALLS) {
            Function f = fit.next();
            Set<Function> called;
            try {
                called = f.getCalledFunctions(monitor);
            } catch (Exception e) {
                continue;
            }
            for (Function c : called) {
                if (ce >= MAX_CALLS) break;
                if (!first) calls.append(",");
                first = false;
                ce++;
                calls.append("{\"src\":").append(js(f.getName()))
                     .append(",\"dst\":").append(js(c.getName()))
                     .append(",\"src_addr\":").append(js(f.getEntryPoint().toString()))
                     .append(",\"dst_addr\":").append(js(c.getEntryPoint().toString()))
                     .append("}");
            }
        }
        calls.append("]");

        // imports / exports / symbols via the symbol table
        StringBuilder imports = new StringBuilder("[");
        boolean fi = true;
        StringBuilder exports = new StringBuilder("[");
        boolean fe = true;
        StringBuilder symbols = new StringBuilder("[");
        boolean fs = true;
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator sit = st.getAllSymbols(true);
        while (sit.hasNext()) {
            Symbol sym = sit.next();
            String kind = "local";
            if (sym.isExternal()) {
                kind = "import";
                if (!fi) imports.append(",");
                fi = false;
                imports.append("{\"name\":").append(js(sym.getName())).append(",\"library\":\"\"}");
            } else if (sym.isGlobal()) {
                kind = "export";
                if (!fe) exports.append(",");
                fe = false;
                exports.append("{\"name\":").append(js(sym.getName()))
                       .append(",\"address\":").append(js(sym.getAddress().toString())).append("}");
            }
            if (!fs) symbols.append(",");
            fs = false;
            symbols.append("{\"name\":").append(js(sym.getName()))
                   .append(",\"type\":").append(js(sym.getSymbolType().toString()))
                   .append(",\"address\":").append(js(sym.getAddress().toString()))
                   .append(",\"kind\":").append(js(kind)).append("}");
        }
        imports.append("]");
        exports.append("]");
        symbols.append("]");

        StringBuilder sb = new StringBuilder();
        sb.append("{\"program\":").append(js(currentProgram.getName()))
          .append(",\"language\":").append(js(currentProgram.getLanguageID().toString()))
          .append(",\"architecture\":").append(js(currentProgram.getLanguage().getProcessor().toString()))
          .append(",\"functions\":").append(funcs)
          .append(",\"calls\":").append(calls)
          .append(",\"imports\":").append(imports)
          .append(",\"exports\":").append(exports)
          .append(",\"symbols\":").append(symbols)
          .append(",\"strings\":[]")
          .append(",\"references\":[]")
          .append(",\"jni_registrations\":[]")
          .append("}");

        try (Writer w = new FileWriter(outPath)) {
            w.write(sb.toString());
        }
        println("ExportDeepNative wrote " + outPath);
    }

    static String js(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        b.append("\"");
        return b.toString();
    }
}
