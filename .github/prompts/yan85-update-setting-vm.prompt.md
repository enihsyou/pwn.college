---
description: "Recover a Yan85 VM encoding from a binary and update setting_vm(vm) in a Python client."
argument-hint: "<binary_path> <client_py_path>"
agent: "IDA Reverse Engineer"
tools:
  - "read"
  - "search"
  - "edit"
  - "idalib-mcp/*"
  - "pylance-mcp-server/*"
---

# Update a Yan85 VM encoding

Arguments:

- `$1` = path to a binary containing a Yan85 interpreter
- `$2` = path to the Python client containing `setting_vm(vm)`

Use the workspace Yan85 skill at [Yan85 VM encoding recovery](../skills/yan85-vm/SKILL.md). Recover the encoding from `$1`, then update only the body of `setting_vm(vm)` in `$2`. This prompt explicitly authorizes that source edit and no other source-file changes.

The skill's narrow scope, evidence rules, IDA MCP call budget, mutation policy, and source-edit restrictions override the generic agent defaults. If any required value remains unresolved, do not modify `$2` and return one concise failure stating which encoding is unresolved.

## Silent execution

Do not narrate steps, progress, tool calls, intermediate findings, hypotheses, or analysis. Suppress all status, transition, and recap text. The only output is the success block below, or the single concise failure line — nothing else.

```text
已更新 setting_vm in <path>:
- layout:  (arg?, arg?, opcode)
- opcode:  IMM=0x?? ADD=0x?? STK=0x?? STM=0x?? LDM=0x?? CMP=0x?? JMP=0x?? SYS=0x??
- reg:     a=0x?? b=0x?? c=0x?? d=0x?? s=0x?? i=0x?? f=0x?? none=0x??
- syscall: <NAME>=0x?? ...
```

Replace every placeholder with recovered values. On the syscall line, include only the syscall mappings supported by the target's `interpret_sys` dispatcher; common names include `OPEN`, `READ_CODE`, `READ_MEMORY`, `WRITE`, `SLEEP`, and `EXIT`, but they are not assumed to all exist. Do not append generic agent sections, next steps, workflow recaps, seccomp or exploitability commentary, or unrelated suggestions.

Example invocation:

```text
/yan85-update-setting-vm toddlersys_level3.1.ko challenges/system-security/system-exploitation/level-3-0/flag.py
```
