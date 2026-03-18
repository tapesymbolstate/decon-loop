// Ghidra headless script: export function boundaries, xrefs, and call graph
// Lighter than full decompile — good for initial mapping
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportFunctionInfo extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp/ghidra-export";

        File outDir = new File(outputDir);
        outDir.mkdirs();

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int total = currentProgram.getFunctionManager().getFunctionCount();

        // Function boundaries
        PrintWriter funcWriter = new PrintWriter(new FileWriter(new File(outDir, "function_boundaries.tsv")));
        funcWriter.println("name\tentry_address\tend_address\tsize\tparam_count\treturn_type\tcalling_convention\tis_thunk\tis_external");

        // Call graph
        PrintWriter callWriter = new PrintWriter(new FileWriter(new File(outDir, "call_graph.tsv")));
        callWriter.println("caller_name\tcaller_address\tcallee_name\tcallee_address\tref_type");

        int count = 0;
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            count++;

            if (count % 5000 == 0) {
                println("Processing: " + count + "/" + total);
            }

            // Function info
            funcWriter.println(
                func.getName() + "\t" +
                func.getEntryPoint() + "\t" +
                func.getBody().getMaxAddress() + "\t" +
                func.getBody().getNumAddresses() + "\t" +
                func.getParameterCount() + "\t" +
                func.getReturnType().getName() + "\t" +
                func.getCallingConventionName() + "\t" +
                func.isThunk() + "\t" +
                func.isExternal()
            );

            // Outgoing calls from this function
            for (Function called : func.getCalledFunctions(monitor)) {
                callWriter.println(
                    func.getName() + "\t" +
                    func.getEntryPoint() + "\t" +
                    called.getName() + "\t" +
                    called.getEntryPoint() + "\t" +
                    "CALL"
                );
            }
        }

        funcWriter.close();
        callWriter.close();

        println("Export complete: " + count + " functions, output at " + outDir.getAbsolutePath());
    }
}
