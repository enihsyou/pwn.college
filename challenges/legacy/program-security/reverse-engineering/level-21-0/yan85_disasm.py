import re

bytecode = """
20 08 3F 20 10 B6 20 20  0A 20 01 01 01 10 40 20
01 01 01 20 00 20 10 9A  20 20 1C 20 01 01 01 10
"""


# ── Yan85 VM Bytecode Disassembler ──────────────────────────────────


_REG_DECODE = {
    1: "a",
    16: "b",
    32: "c",
    64: "d",
    4: "f",
    8: "i",
    2: "s",
}
_FLAG_BITS = [(8, "L"), (2, "G"), (4, "E"), (0x10, "N"), (1, "Z")]


def _name_register(val: int) -> str:
    if val == 0:
        return "NONE"
    return _REG_DECODE.get(val, "?")


def _describe_flags(val: int) -> str:
    if val == 0:
        return "*"
    chars = [ch for bit, ch in _FLAG_BITS if val & bit]
    return "".join(chars) if chars else f"{val:#x}"


def _fmt_imm(arg1: int, arg2: int) -> str:
    return f"IMM {_name_register(arg1)} = {arg2:#04x}"


def _fmt_add(arg1: int, arg2: int) -> str:
    return f"ADD {_name_register(arg1)} {_name_register(arg2)}"


def _fmt_stk(arg1: int, arg2: int) -> str:
    return f"STK {_name_register(arg1)} {_name_register(arg2)}"


def _fmt_stm(arg1: int, arg2: int) -> str:
    return f"STM *{_name_register(arg1)} = {_name_register(arg2)}"


def _fmt_ldm(arg1: int, arg2: int) -> str:
    return f"LDM {_name_register(arg1)} = *{_name_register(arg2)}"


def _fmt_cmp(arg1: int, arg2: int) -> str:
    return f"CMP {_name_register(arg1)} {_name_register(arg2)}"


def _fmt_jmp(arg1: int, arg2: int) -> str:
    return f"JMP {_describe_flags(arg1)} {_name_register(arg2)}"


def _fmt_sys(arg1: int, arg2: int) -> str:
    return f"SYS {arg1:#04x} {_name_register(arg2)}"


_INSTR_TABLE = [
    (0x01, _fmt_cmp),
    (0x02, _fmt_add),
    (0x04, _fmt_sys),
    (0x08, _fmt_ldm),
    (0x10, _fmt_stm),
    (0x20, _fmt_jmp),
    (0x40, _fmt_imm),
    (0x80, _fmt_stk),
]


def format_instruction(opcode: int, arg1: int, arg2: int) -> str:
    for bit, fmt_fn in _INSTR_TABLE:
        if opcode & bit:
            return fmt_fn(arg1, arg2)
    return f"??? op={opcode:#04x} a1={arg1:#04x} a2={arg2:#04x}"


def disassemble(bytecode_str: str) -> None:
    hex_str = re.sub(r"\s+", " ", bytecode_str.strip())
    data = bytes.fromhex(hex_str)

    for i in range(0, len(data), 3):
        if i + 2 >= len(data):
            break
        opcode, arg1, arg2 = data[i : i + 3]
        print(f"{i:#06x}:  {format_instruction(opcode, arg1, arg2)}")


if __name__ == "__main__":
    disassemble(bytecode)
