import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class DecompileAllParallel extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp/ghidra-decompiled";

        File outDir = new File(outputDir);
        outDir.mkdirs();

        int threadCount = Runtime.getRuntime().availableProcessors();
        println("CPU cores available: " + threadCount);

        // Collect all functions
        List<Function> funcList = new ArrayList<>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            funcList.add(functions.next());
        }
        int total = funcList.size();
        println("Total functions: " + total + ", threads: " + threadCount);

        File funcsDir = new File(outDir, "functions");
        funcsDir.mkdirs();

        // Check for resume: which functions already have individual files
        Set<String> alreadyDone = new HashSet<>();
        if (funcsDir.exists()) {
            for (File subDir : funcsDir.listFiles()) {
                if (subDir.isDirectory()) {
                    for (File f : subDir.listFiles()) {
                        if (f.getName().endsWith(".c")) {
                            alreadyDone.add(f.getName());
                        }
                    }
                }
            }
        }
        if (!alreadyDone.isEmpty()) {
            println("Resume mode: " + alreadyDone.size() + " functions already decompiled, skipping them");
        }

        // Filter out already-done functions
        List<Function> todo = new ArrayList<>();
        for (Function f : funcList) {
            String addrHex = f.getEntryPoint().toString();
            String safeName = f.getName().replaceAll("[^a-zA-Z0-9_]", "_");
            String fileName = safeName + "_" + addrHex + ".c";
            if (!alreadyDone.contains(fileName)) {
                todo.add(f);
            }
        }
        println("Functions to decompile: " + todo.size());

        AtomicInteger counter = new AtomicInteger(0);
        AtomicInteger errorCount = new AtomicInteger(0);

        // Index: collect all entries (including already-done ones will be from funcList)
        ConcurrentLinkedQueue<String> indexLines = new ConcurrentLinkedQueue<>();

        // Thread pool
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<?>> futures = new ArrayList<>();

        // Split work
        int chunkSize = Math.max(1, (todo.size() + threadCount - 1) / threadCount);
        for (int t = 0; t < threadCount; t++) {
            int start = t * chunkSize;
            if (start >= todo.size()) break;
            int end = Math.min(start + chunkSize, todo.size());
            List<Function> chunk = todo.subList(start, end);

            futures.add(executor.submit(() -> {
                try {
                    DecompInterface decomp = new DecompInterface();
                    decomp.openProgram(currentProgram);
                    decomp.setSimplificationStyle("decompile");

                    for (Function func : chunk) {
                        if (monitor.isCancelled()) break;

                        int c = counter.incrementAndGet();
                        if (c % 2000 == 0) {
                            println("Progress: " + c + "/" + todo.size() + " (" +
                                    (c * 100 / todo.size()) + "%) - " + func.getName());
                        }

                        try {
                            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
                            if (results != null && results.decompileCompleted()) {
                                String code = results.getDecompiledFunction().getC();
                                if (code != null && !code.isEmpty()) {
                                    String addrHex = func.getEntryPoint().toString();
                                    String subDirName = addrHex.length() > 3 ?
                                            addrHex.substring(0, addrHex.length() - 3) : "misc";
                                    File funcSubDir = new File(funcsDir, subDirName);
                                    funcSubDir.mkdirs();

                                    String safeName = func.getName().replaceAll("[^a-zA-Z0-9_]", "_");
                                    File outFile = new File(funcSubDir, safeName + "_" + addrHex + ".c");
                                    try (PrintWriter w = new PrintWriter(new FileWriter(outFile))) {
                                        w.println("// " + func.getName() + " @ " + addrHex);
                                        w.println(code);
                                    }
                                }
                            }
                        } catch (Exception e) {
                            errorCount.incrementAndGet();
                        }
                    }

                    decomp.dispose();
                } catch (Exception e) {
                    println("Thread error: " + e.getMessage());
                }
            }));
        }

        // Wait for completion
        for (Future<?> f : futures) {
            f.get();
        }
        executor.shutdown();

        // Build index from ALL functions (including previously done)
        println("Building function index...");
        try (PrintWriter indexWriter = new PrintWriter(new FileWriter(new File(outDir, "function_index.tsv")))) {
            indexWriter.println("name\taddress\tsize\tparams\treturn_type");
            for (Function func : funcList) {
                indexWriter.println(
                    func.getName() + "\t" +
                    func.getEntryPoint() + "\t" +
                    func.getBody().getNumAddresses() + "\t" +
                    func.getParameterCount() + "\t" +
                    func.getReturnType().getName()
                );
            }
        }

        // Build combined file from individual files
        println("Building combined decompilation file...");
        try (PrintWriter allWriter = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "all_decompiled.c")), 1024 * 1024))) {
            allWriter.println("// Ghidra decompilation of: " + currentProgram.getName());
            allWriter.println("// Functions: " + total);
            allWriter.println();

            for (File subDir : funcsDir.listFiles()) {
                if (!subDir.isDirectory()) continue;
                File[] cFiles = subDir.listFiles((d, name) -> name.endsWith(".c"));
                if (cFiles == null) continue;
                Arrays.sort(cFiles);
                for (File cf : cFiles) {
                    try (BufferedReader reader = new BufferedReader(new FileReader(cf))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            allWriter.println(line);
                        }
                        allWriter.println();
                    }
                }
            }
        }

        println("Decompilation complete: " + counter.get() + " new + " + alreadyDone.size() +
                " cached = " + total + " total (" + errorCount.get() + " errors)");
        println("Output: " + outDir.getAbsolutePath());
    }
}
