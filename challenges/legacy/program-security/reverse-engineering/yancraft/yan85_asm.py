import re

_REG_ENCODE = {
    "a": 8,
    "b": 16,
    "c": 2,
    "d": 32,
    "f": 4,
    "i": 64,
    "s": 1,
    "none": 0,
}

_OPCODES = {
    "CMP": 0x01,
    "ADD": 0x02,
    "SYS": 0x04,
    "LDM": 0x08,
    "STM": 0x10,
    "JMP": 0x20,
    "IMM": 0x40,
    "STK": 0x80,
}

_FLAG_ENCODE = {
    "L": 8,
    "G": 2,
    "E": 4,
    "N": 0x10,
    "Z": 1,
    "*": 0,
}


def _reg_value(name: str) -> int:
    key = name.strip().lower()
    if key not in _REG_ENCODE:
        raise ValueError(f"Unknown register: {name}")
    return _REG_ENCODE[key]


def _parse_imm(token: str) -> int:
    val = int(token, 0)
    if not 0 <= val <= 0xFF:
        raise ValueError(f"Immediate out of byte range: {token}")
    return val


def _parse_flags(token: str) -> int:
    token = token.strip().upper()
    if token == "*":
        return 0
    bits = 0
    for ch in token:
        if ch not in _FLAG_ENCODE or ch == "*":
            raise ValueError(f"Unknown flag char: {ch}")
        bits |= _FLAG_ENCODE[ch]
    return bits


def assemble_line(line: str) -> tuple[int, int, int]:
    s = line.strip()
    if not s:
        raise ValueError("Empty instruction")

    m = re.fullmatch(r"IMM\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["IMM"], _reg_value(m.group(1)), _parse_imm(m.group(2))

    m = re.fullmatch(r"ADD\s+(\w+)\s+(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["ADD"], _reg_value(m.group(1)), _reg_value(m.group(2))

    m = re.fullmatch(r"CMP\s+(\w+)\s+(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["CMP"], _reg_value(m.group(1)), _reg_value(m.group(2))

    m = re.fullmatch(r"LDM\s+(\w+)\s*=\s*\*(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["LDM"], _reg_value(m.group(1)), _reg_value(m.group(2))

    m = re.fullmatch(r"STM\s*\*(\w+)\s*=\s*(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["STM"], _reg_value(m.group(1)), _reg_value(m.group(2))

    m = re.fullmatch(r"STK\s+(\w+)\s+(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["STK"], _reg_value(m.group(1)), _reg_value(m.group(2))

    m = re.fullmatch(r"JMP\s+([A-Za-z*]+)\s+(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["JMP"], _parse_flags(m.group(1)), _reg_value(m.group(2))

    m = re.fullmatch(r"SYS\s+(0x[0-9a-fA-F]+|\d+)\s+(\w+)", s, re.IGNORECASE)
    if m:
        return _OPCODES["SYS"], _parse_imm(m.group(1)), _reg_value(m.group(2))

    raise ValueError(f"Cannot parse instruction: {line}")


def assemble(asm_text: str) -> bytes:
    out = bytearray()
    for raw in asm_text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        opcode, arg1, arg2 = assemble_line(line)
        out.extend((arg1, opcode, arg2))
    return bytes(out)
