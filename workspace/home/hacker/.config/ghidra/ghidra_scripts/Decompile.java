import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

public class Decompile extends GhidraScript {

    private static final int TIMEOUT_SECONDS = 60;
    private static final int MAX_LINE_WIDTH = 160;
    private static final int MAX_PROBED_STRING_BYTES = 4096;
    private static final char KERNEL_LOG_PREFIX = 0x01;

    private static final String[] AUTO_DATA_REFERENCE_PREFIXES = {
        "&DAT_", "&byte_", "&word_", "&dword_", "&qword_"
    };

    private enum CState { CODE, STRING, CHARACTER, LINE_COMMENT, BLOCK_COMMENT }

    private static final class Summary {
        int processed;
        int succeeded;
        int failed;
        int inlinedStrings;
        int inlinedKernelLogStrings;
    }

    private static final class DataReference {
        final int end;
        final String hexAddress;

        DataReference(int end, String hexAddress) {
            this.end = end;
            this.hexAddress = hexAddress;
        }
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
                throw new IllegalStateException("Unable to initialize the decompiler: " + decompiler.getLastMessage());
            }

            Summary summary = writeFunctions(decompiler, output);
            println("Decompiled " + summary.succeeded + " of " + summary.processed + " internal functions");
            println("Inlined " + summary.inlinedStrings + " string reference(s), including " +
                summary.inlinedKernelLogStrings + " kernel log string(s)");

            if (summary.failed != 0) {
                printerr(summary.failed + " function(s) could not be decompiled");
            }
            if (summary.succeeded == 0) {
                throw new IllegalStateException("No functions were successfully decompiled");
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
            throw new IllegalArgumentException("Usage: Decompile.java <output-file>");
        }
        return new File(args[0]).getAbsoluteFile().toPath().normalize();
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

    private void configureDecompiler(DecompInterface decompiler, DecompileOptions options) {
        decompiler.setOptions(options);
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(false);
        decompiler.setSimplificationStyle("decompile");
    }

    private Summary writeFunctions(DecompInterface decompiler, Path output) throws Exception {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);
        int total = functionManager.getFunctionCount();
        Summary summary = new Summary();

        try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
            boolean firstFunction = true;

            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function function = functions.next();
                if (function.isExternal()) {
                    continue;
                }

                summary.processed++;
                monitor.setMessage("Decompiling " + function.getName() + " (" + summary.processed + "/" + total + ")");

                DecompileResults result = decompiler.decompileFunction(function, TIMEOUT_SECONDS, monitor);
                String code = getCode(result);
                if (code == null) {
                    summary.failed++;
                    printerr(function.getName() + " at " + function.getEntryPoint() + ": " + getFailureMessage(result));
                    continue;
                }

                if (!firstFunction) {
                    writer.write("\n\n");
                }
                writer.write(inlineStringReferences(code, summary));
                firstFunction = false;
                summary.succeeded++;
            }
        }

        return summary;
    }

    private String getCode(DecompileResults result) {
        if (result == null || !result.decompileCompleted() || result.getDecompiledFunction() == null) {
            return null;
        }
        String code = result.getDecompiledFunction().getC();
        return code == null || code.isBlank() ? null : code;
    }

    private String getFailureMessage(DecompileResults result) {
        if (result == null) {
            return "the decompiler returned no result";
        }
        String message = result.getErrorMessage();
        return message == null || message.isBlank() ? "decompilation did not complete" : message.strip();
    }

    private String inlineStringReferences(String code, Summary summary) {
        StringBuilder output = new StringBuilder(code.length());
        CState state = CState.CODE;

        for (int i = 0; i < code.length();) {
            char current = code.charAt(i);

            if (state == CState.CODE) {
                if (current == '"') {
                    output.append(current);
                    state = CState.STRING;
                    i++;
                    continue;
                }
                if (current == '\'') {
                    output.append(current);
                    state = CState.CHARACTER;
                    i++;
                    continue;
                }
                if (current == '/' && i + 1 < code.length() && code.charAt(i + 1) == '/') {
                    output.append("//");
                    state = CState.LINE_COMMENT;
                    i += 2;
                    continue;
                }
                if (current == '/' && i + 1 < code.length() && code.charAt(i + 1) == '*') {
                    output.append("/*");
                    state = CState.BLOCK_COMMENT;
                    i += 2;
                    continue;
                }

                DataReference reference = findAutoDataReference(code, i);
                if (reference != null) {
                    String expression = resolveStringExpression(reference.hexAddress, summary);
                    if (expression != null) {
                        output.append(expression);
                        summary.inlinedStrings++;
                        i = reference.end;
                        continue;
                    }
                }

                output.append(current);
                i++;
                continue;
            }

            output.append(current);
            i++;

            if ((state == CState.STRING || state == CState.CHARACTER) && current == '\\' && i < code.length()) {
                output.append(code.charAt(i));
                i++;
                continue;
            }
            if (state == CState.STRING && current == '"') {
                state = CState.CODE;
            }
            else if (state == CState.CHARACTER && current == '\'') {
                state = CState.CODE;
            }
            else if (state == CState.LINE_COMMENT && (current == '\n' || current == '\r')) {
                state = CState.CODE;
            }
            else if (state == CState.BLOCK_COMMENT && current == '*' && i < code.length() && code.charAt(i) == '/') {
                output.append('/');
                i++;
                state = CState.CODE;
            }
        }

        return output.toString();
    }

    private DataReference findAutoDataReference(String code, int start) {
        if (start > 0 && code.charAt(start - 1) == '&') {
            return null;
        }

        for (String prefix : AUTO_DATA_REFERENCE_PREFIXES) {
            if (!code.startsWith(prefix, start)) {
                continue;
            }

            int hexStart = start + prefix.length();
            int end = hexStart;
            while (end < code.length() && isHexDigit(code.charAt(end))) {
                end++;
            }

            if (end != hexStart && (end == code.length() || !isIdentifierPart(code.charAt(end)))) {
                return new DataReference(end, code.substring(hexStart, end));
            }
        }

        return null;
    }

    private String resolveStringExpression(String hexAddress, Summary summary) {
        try {
            long offset = Long.parseUnsignedLong(hexAddress, 16);
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
            byte[] bytes = readTerminatedBytes(address);
            if (bytes == null || !isPlausibleString(bytes)) {
                return null;
            }

            String level = getKernelLogLevelMacro(bytes);
            if (level != null) {
                summary.inlinedKernelLogStrings++;
                return level + " " + toCStringLiteral(bytes, 2);
            }
            return toCStringLiteral(bytes, 0);
        }
        catch (RuntimeException exception) {
            return null;
        }
    }

    private byte[] readTerminatedBytes(Address start) {
        Memory memory = currentProgram.getMemory();
        MemoryBlock block = memory.getBlock(start);
        if (block == null || !block.isInitialized()) {
            return null;
        }

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            for (int i = 0; i <= MAX_PROBED_STRING_BYTES; i++) {
                Address current = start.add(i);
                if (!block.contains(current)) {
                    return null;
                }

                int value = memory.getByte(current) & 0xff;
                if (value == 0) {
                    return bytes.size() >= 2 ? bytes.toByteArray() : null;
                }
                if (i == MAX_PROBED_STRING_BYTES) {
                    return null;
                }
                bytes.write(value);
            }
        }
        catch (MemoryAccessException | RuntimeException exception) {
            return null;
        }

        return null;
    }

    private boolean isPlausibleString(byte[] bytes) {
        if (bytes.length < 2 || bytes.length > MAX_PROBED_STRING_BYTES) {
            return false;
        }

        int readable = 0;
        int printable = 0;

        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            if (value >= 0x20 && value <= 0x7e) {
                readable++;
                printable++;
            }
            else if (value == '\t' || value == '\n' || value == '\r' || value == '\f' || value == 0x0b ||
                    value == 0x07 || value == 0x08 || i == 0 && value == KERNEL_LOG_PREFIX) {
                readable++;
            }
        }

        return printable != 0 && readable * 4 >= bytes.length * 3;
    }

    private String getKernelLogLevelMacro(byte[] bytes) {
        if (bytes.length < 2 || (bytes[0] & 0xff) != KERNEL_LOG_PREFIX) {
            return null;
        }

        switch (bytes[1] & 0xff) {
            case '0': return "KERN_EMERG";
            case '1': return "KERN_ALERT";
            case '2': return "KERN_CRIT";
            case '3': return "KERN_ERR";
            case '4': return "KERN_WARNING";
            case '5': return "KERN_NOTICE";
            case '6': return "KERN_INFO";
            case '7': return "KERN_DEBUG";
            case 'd': return "KERN_DEFAULT";
            case 'c': return "KERN_CONT";
            default: return null;
        }
    }

    private String toCStringLiteral(byte[] bytes, int start) {
        StringBuilder literal = new StringBuilder(bytes.length - start + 2);
        literal.append('"');

        for (int i = start; i < bytes.length; i++) {
            int value = bytes[i] & 0xff;
            switch (value) {
                case 0x07: literal.append("\\a"); break;
                case 0x08: literal.append("\\b"); break;
                case 0x09: literal.append("\\t"); break;
                case 0x0a: literal.append("\\n"); break;
                case 0x0b: literal.append("\\v"); break;
                case 0x0c: literal.append("\\f"); break;
                case 0x0d: literal.append("\\r"); break;
                case '"': literal.append("\\\""); break;
                case '\\': literal.append("\\\\"); break;
                default:
                    if (value >= 0x20 && value <= 0x7e) {
                        literal.append((char) value);
                    }
                    else {
                        appendOctalEscape(literal, value);
                    }
                    break;
            }
        }

        return literal.append('"').toString();
    }

    private void appendOctalEscape(StringBuilder output, int value) {
        output.append('\\');
        output.append((char) ('0' + ((value >>> 6) & 7)));
        output.append((char) ('0' + ((value >>> 3) & 7)));
        output.append((char) ('0' + (value & 7)));
    }

    private boolean isHexDigit(char value) {
        return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F';
    }

    private boolean isIdentifierPart(char value) {
        return value == '_' || Character.isLetterOrDigit(value);
    }
}