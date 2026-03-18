// Ghidra headless script: decompile all functions and export as C pseudocode
// Usage: analyzeHeadless <project_dir> <project_name> -import <binary> -postScript DecompileAll.java <output_dir>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileAll extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp/ghidra-decompiled";

        File outDir = new File(outputDir);
        outDir.mkdirs();

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        int total = currentProgram.getFunctionManager().getFunctionCount();

        // Export function list
        PrintWriter indexWriter = new PrintWriter(new FileWriter(new File(outDir, "function_index.tsv")));
        indexWriter.println("name\taddress\tsize\tparams\treturn_type");

        // Export all decompiled functions into a single file + individual files
        PrintWriter allWriter = new PrintWriter(new FileWriter(new File(outDir, "all_decompiled.c")));
        allWriter.println("// Ghidra decompilation of: " + currentProgram.getName());
        allWriter.println("// Functions: " + total);
        allWriter.println();

        File funcsDir = new File(outDir, "functions");
        funcsDir.mkdirs();

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            count++;

            if (count % 1000 == 0) {
                println("Decompiling: " + count + "/" + total + " - " + func.getName());
            }

            // Index entry
            indexWriter.println(
                func.getName() + "\t" +
                func.getEntryPoint() + "\t" +
                func.getBody().getNumAddresses() + "\t" +
                func.getParameterCount() + "\t" +
                func.getReturnType().getName()
            );

            // Decompile
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                if (code != null && !code.isEmpty()) {
                    // Write to combined file
                    allWriter.println("// === " + func.getName() + " @ " + func.getEntryPoint() + " ===");
                    allWriter.println(code);
                    allWriter.println();

                    // Write individual function file (batch by first 3 hex chars of address)
                    String addrHex = func.getEntryPoint().toString();
                    String subDir = addrHex.length() > 3 ? addrHex.substring(0, addrHex.length() - 3) : "misc";
                    File funcSubDir = new File(funcsDir, subDir);
                    funcSubDir.mkdirs();

                    String safeName = func.getName().replaceAll("[^a-zA-Z0-9_]", "_");
                    PrintWriter funcWriter = new PrintWriter(
                        new FileWriter(new File(funcSubDir, safeName + "_" + addrHex + ".c"))
                    );
                    funcWriter.println("// " + func.getName() + " @ " + addrHex);
                    funcWriter.println(code);
                    funcWriter.close();
                }
            }
        }

        indexWriter.close();
        allWriter.close();
        decomp.dispose();

        println("Decompilation complete: " + count + " functions processed");
        println("Output: " + outDir.getAbsolutePath());
    }
}
