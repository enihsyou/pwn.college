---
name: yan85-vm
description: "Recover Yan85 instruction layout, opcode, register, and syscall encodings from a binary, optionally updating setting_vm(vm) in a Python client."
user-invocable: false
disable-model-invocation: false
---

# Yan85 VM encoding recovery

Recover the Yan85 VM encoding required by `setting_vm(vm)` from a binary containing a Yan85 interpreter. The target may be a kernel module, a user-mode executable, or another binary format.

Recover four categories:

1. instruction layout
2. opcode encodings
3. register encodings
4. syscall encodings

This skill supports analysis-only recovery and recovery followed by a narrowly authorized Python-client update.

## Scope and evidence rules

This is an intentionally narrow encoding-recovery workflow, not general vulnerability analysis. Do not investigate exploitability, seccomp bypasses, privilege escalation, ioctl attack surfaces, exploit strategy, unrelated interpreter internals, or syscall restrictions beyond what identifies the canonical syscall mapping.

Do not decompile unrelated functions merely because they look interesting. In particular, do not recursively inspect `sys_open`, `sys_read`, `sys_write`, `yan85_seccomp_validate`, `device_ioctl*`, or `interpreter_loop` unless one is itself the minimal dispatcher or helper required for one of the four encoding categories.

Do not rename functions, add unrelated comments, retype broad parts of the IDB, or otherwise annotate the IDB during this workflow. Treat unresolved values as unresolved; never invent a mapping.

## Instruction layout

Recover the byte/field ordering of `arg1`, `arg2`, and `opcode` using this evidence priority:

```text
instruction_t type/layout
    ↓
interpret_instruction field accesses / unpacking
    ↓
decoder helper only if necessary
```

When IDA exposes `struct instruction_t`, inspect its actual type definition and field layout as the authoritative primary source. If it is unavailable, incomplete, anonymous, or has lost useful type information, infer the layout from `interpret_instruction`, especially its prologue, field accesses, and decoding or unpacking logic. Inspect one decoder/unpack helper only when those sources are insufficient.

## Opcode encodings

Recover all eight opcode encodings: `IMM`, `ADD`, `STK`, `STM`, `LDM`, `CMP`, `JMP`, and `SYS`.

Prefer encoding information associated with `struct instruction_t` when it is represented in the type or directly recoverable from a related typed representation. Otherwise, recover opcode masks or values from dispatch logic in `interpret_instruction`. Map each opcode by branch semantics, never by source or switch ordering.

## Register encodings

Recover all eight register encodings: `a`, `b`, `c`, `d`, `s`, `i`, `f`, and `none`.

Inspect `read_register` or the equivalent register-decoding helper in an obfuscated build. Map values by actual VM register semantics, not branch ordering.

## Syscall encodings

Recover the syscall encodings that are actually present in the target's dispatcher. `OPEN`, `READ_CODE`, `READ_MEMORY`, `WRITE`, `SLEEP`, and `EXIT` are common canonical Yan85 syscall names, not a required or exhaustive set; a target may contain only some of them or additional operations.

Inspect `interpret_sys` or the equivalent syscall dispatcher. Syscall names are not fixed by ordering. Map branches using evidence visible in the dispatcher, including direct callee or import names, state method names, arguments, source/destination direction, memory accesses, and return handling. Symbols such as `state->sys_open`, `state->sys_exit`, `state->sys_sleep`, `kernel_read`, or `kernel_write` are useful examples, but must not be assumed to survive in every binary.

Do not recursively reverse-engineer syscall implementation functions merely to distinguish an encoding. Report only operations and encodings supported by dispatcher evidence. If a present branch cannot be mapped, mark it unresolved and do not expand the investigation; do not treat a syscall that is genuinely absent from the dispatcher as unresolved.

## Efficient IDA workflow

Center the investigation on:

- `struct instruction_t` and related IDA type information
- `interpret_instruction`
- `read_register` or its equivalent
- `interpret_sys` or its equivalent

Optimize for the minimum useful IDA MCP calls instead of requiring an exact decompile count. One additional decoder/unpack helper is allowed only when instruction layout cannot be recovered from primary evidence.

Avoid `disasm`, `get_int`, `get_bytes`, `xrefs_to`, `search_text`, and other instruction-level or broad exploratory APIs in the normal workflow. Use one only if primary evidence cannot establish a required encoding and the call remains within this narrow scope.

The normal target is at most 6 IDA MCP calls. When the generic Agent's `idb_open` workflow requires mode retries, the hard maximum is 8 IDA MCP calls. Do not make extra calls merely to consume either budget. The final source edit is not an IDA MCP call.

## Updating a Python client

Modify a Python client only when explicitly requested or when a user-facing prompt supplies a client path for that purpose. The edit must be based on recovered evidence.

When authorized:

- edit only the body of `setting_vm(vm)`
- preserve all unrelated code
- do not modify `ctf()` or `compile_bytecode()`
- do not rewrite exploit logic, imports, or unrelated helpers
- do not run the exploit
- do not call `vm.disassemble()` for validation unless explicitly requested
- do not perform unrelated cleanup or refactoring

If any required encoding remains unresolved, report the unresolved category or value and do not write fabricated values into `setting_vm(vm)`.

## Result contract

For analysis-only use, report the four recovered categories and any unresolved values concisely. When a task-specific prompt defines a stricter output contract, follow that contract instead.
