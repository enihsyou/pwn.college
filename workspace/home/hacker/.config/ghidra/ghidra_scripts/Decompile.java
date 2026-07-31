import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileOptions.BraceStyle;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class Decompile extends GhidraScript {

    private static final int TIMEOUT_SECONDS = 60;
    private static final int MAX_LINE_WIDTH = 120;

    private static final class Summary {
        int processed;
        int succeeded;
        int failed;
    }

    @Override
    public void run() throws Exception {
        Path output = getOutputPath();
        Path parent = output.getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        DecompileOptions options = createOptions();
        DecompInterface decompiler = new DecompInterface();

        try {
            configureDecompiler(decompiler, options);

            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(
                    "Unable to initialize the decompiler: " +
                    decompiler.getLastMessage()
                );
            }

            Summary summary = writeFunctions(decompiler, output);

            println(
                "Decompiled " +
                summary.succeeded +
                " of " +
                summary.processed +
                " internal functions"
            );

            if (summary.failed != 0) {
                printerr(
                    summary.failed +
                    " function(s) could not be decompiled"
                );
            }

            if (summary.succeeded == 0) {
                throw new IllegalStateException(
                    "No functions were successfully decompiled"
                );
            }

            println("Saved to: " + output);
        }
        finally {
            decompiler.dispose();
        }
    }

    private Path getOutputPath() {
        String[] args = getScriptArgs();

        if (args.length != 1) {
            throw new IllegalArgumentException(
                "Usage: Decompile.java <output-file>"
            );
        }

        return new File(args[0])
            .getAbsoluteFile()
            .toPath()
            .normalize();
    }

    private DecompileOptions createOptions() {
        DecompileOptions options = new DecompileOptions();

        options.grabFromProgram(currentProgram);
        options.setDefaultTimeout(TIMEOUT_SECONDS);
        options.setMaxWidth(MAX_LINE_WIDTH);

        options.setFunctionBraceFormat(BraceStyle.Next);
        options.setIfElseBraceFormat(BraceStyle.Same);
        options.setLoopBraceFormat(BraceStyle.Same);
        options.setSwitchBraceFormat(BraceStyle.Same);

        options.setPRECommentIncluded(false);
        options.setPLATECommentIncluded(false);
        options.setPOSTCommentIncluded(false);
        options.setEOLCommentIncluded(false);
        options.setHeadCommentIncluded(false);

        return options;
    }

    private void configureDecompiler(
            DecompInterface decompiler,
            DecompileOptions options) {

        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");
    }

    private Summary writeFunctions(
            DecompInterface decompiler,
            Path output) throws Exception {

        FunctionManager functionManager =
            currentProgram.getFunctionManager();

        FunctionIterator functions =
            functionManager.getFunctions(true);

        int total = functionManager.getFunctionCount();
        Summary summary = new Summary();

        try (
            BufferedWriter writer = Files.newBufferedWriter(
                output,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE
            )
        ) {
            boolean firstFunction = true;

            while (functions.hasNext()) {
                monitor.checkCancelled();

                Function function = functions.next();

                if (function.isExternal()) {
                    continue;
                }

                summary.processed++;

                monitor.setMessage(
                    "Decompiling " +
                    function.getName() +
                    " (" +
                    summary.processed +
                    "/" +
                    total +
                    ")"
                );

                DecompileResults result =
                    decompiler.decompileFunction(
                        function,
                        TIMEOUT_SECONDS,
                        monitor
                    );

                String code = getCode(result);

                if (code == null) {
                    summary.failed++;

                    printerr(
                        function.getName() +
                        " at " +
                        function.getEntryPoint() +
                        ": " +
                        getFailureMessage(result)
                    );

                    continue;
                }

                if (!firstFunction) {
                    writer.write("\n\n\n");
                }

                writer.write(cleanCode(code));

                firstFunction = false;
                summary.succeeded++;
            }

            if (!firstFunction) {
                writer.newLine();
            }
        }

        return summary;
    }

    private String getCode(DecompileResults result) {
        if (result == null || !result.decompileCompleted()) {
            return null;
        }

        if (result.getDecompiledFunction() == null) {
            return null;
        }

        String code = result.getDecompiledFunction().getC();

        if (code == null || code.isBlank()) {
            return null;
        }

        return code;
    }

    private String getFailureMessage(DecompileResults result) {
        if (result == null) {
            return "the decompiler returned no result";
        }

        String message = result.getErrorMessage();

        if (message == null || message.isBlank()) {
            return "decompilation did not complete";
        }

        return message.strip();
    }

    private String cleanCode(String code) {
        String normalized = code
            .replace("\r\n", "\n")
            .replace('\r', '\n')
            .strip();

        String[] lines = normalized.split("\n", -1);
        StringBuilder cleaned = new StringBuilder(normalized.length());

        boolean previousLineWasBlank = false;

        for (String line : lines) {
            String current = line.stripTrailing();
            boolean blank = current.isBlank();

            if (blank && previousLineWasBlank) {
                continue;
            }

            if (cleaned.length() != 0) {
                cleaned.append('\n');
            }

            cleaned.append(current);
            previousLineWasBlank = blank;
        }

        return cleaned.toString().strip();
    }
}
