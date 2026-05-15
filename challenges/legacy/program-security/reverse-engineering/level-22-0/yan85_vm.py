from __future__ import annotations

import re

CANONICAL_REGISTERS = ("a", "b", "c", "d", "s", "i", "f", "none")
CANONICAL_INSTRUCTIONS = ("IMM", "ADD", "STK", "STM", "LDM", "CMP", "JMP", "SYS")
CANONICAL_FLAGS = ("L", "G", "E", "N", "Z")
CANONICAL_SYSCALLS = ("OPEN", "READ_MEMORY", "READ_CODE", "WRITE", "SLEEP", "EXIT")
CANONICAL_INSTRUCTION_LAYOUT = ("opcode", "arg1", "arg2")


def _compile_ci(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _set_encoding(mapping: dict[str, int], key: str, value: int, case: str = "lower") -> None:
    if case == "lower":
        k = key.strip().lower()
    else:
        k = key.strip().upper()
    mapping[k] = value & 0xFF


class Yan85Encoding:
    def __init__(self, instruction_layout: tuple[str, str, str]) -> None:
        self.reg_encode: dict[str, int] = {}
        self.opcode_encode: dict[str, int] = {}
        self.flag_encode: dict[str, int] = {}
        self.sys_encode: dict[str, int] = {}
        self.instruction_layout = self._normalize_layout(instruction_layout)

    @property
    def reg_decode(self) -> dict[int, str]:
        return {value: name for name, value in self.reg_encode.items()}

    @property
    def opcode_decode(self) -> dict[int, str]:
        return {value: name for name, value in self.opcode_encode.items()}

    @property
    def sys_decode(self) -> dict[int, str]:
        return {value: name for name, value in self.sys_encode.items()}

    @staticmethod
    def _normalize_layout(instruction_layout: tuple[str, str, str]) -> tuple[str, str, str]:
        allowed = set(CANONICAL_INSTRUCTION_LAYOUT)
        normalized = tuple(part.strip().lower() for part in instruction_layout)
        if set(normalized) != allowed:
            raise ValueError("instruction_layout must be a permutation of: opcode, arg1, arg2")
        return normalized[0], normalized[1], normalized[2]

    def clone(self) -> "Yan85Encoding":
        enc = Yan85Encoding(self.instruction_layout)
        enc.reg_encode = dict(self.reg_encode)
        enc.opcode_encode = dict(self.opcode_encode)
        enc.flag_encode = dict(self.flag_encode)
        enc.sys_encode = dict(self.sys_encode)
        return enc

    def set_register_encoding(self, register_name: str, value: int) -> None:
        _set_encoding(self.reg_encode, register_name, value, case="lower")

    def set_opcode_encoding(self, instruction_name: str, value: int) -> None:
        _set_encoding(self.opcode_encode, instruction_name, value, case="upper")

    def set_syscall_encoding(self, syscall_name: str, value: int) -> None:
        _set_encoding(self.sys_encode, syscall_name, value, case="upper")

    def set_flag_encoding(self, flag_name: str, value: int) -> None:
        _set_encoding(self.flag_encode, flag_name, value, case="upper")


class Yan85VM:
    _IMM_RE = _compile_ci(r"IMM\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)")
    _ADD_RE = _compile_ci(r"ADD\s+(\w+)\s+(\w+)")
    _STK_RE = _compile_ci(r"STK\s+(\w+)\s+(\w+)")
    _STM_RE = _compile_ci(r"STM\s+\*(\w+)\s*=\s*(\w+)")
    _LDM_RE = _compile_ci(r"LDM\s+(\w+)\s*=\s*\*(\w+)")
    _CMP_RE = _compile_ci(r"CMP\s+(\w+)\s+(\w+)")
    _JMP_RE = _compile_ci(r"JMP\s+([A-Za-z*]+)\s+(\w+)")
    _SYS_RE = _compile_ci(r"SYS\s+([^\s]+)\s+(\w+)")

    def __init__(self, encoding: Yan85Encoding) -> None:
        self.encoding = encoding.clone()

    def encode_instruction_bytes(self, opcode: int, arg1: int, arg2: int) -> bytes:
        values = {
            "opcode": opcode & 0xFF,
            "arg1": arg1 & 0xFF,
            "arg2": arg2 & 0xFF,
        }
        layout = self.encoding.instruction_layout
        return bytes(values[name] for name in layout)

    def decode_instruction_bytes(self, chunk: bytes) -> tuple[int, int, int]:
        if len(chunk) != 3:
            raise ValueError("Instruction chunk must be exactly 3 bytes")
        mapped = {name: chunk[idx] for idx, name in enumerate(self.encoding.instruction_layout)}
        return mapped["opcode"], mapped["arg1"], mapped["arg2"]

    def reg_value(self, name: str) -> int:
        key = name.strip().lower()
        if key not in self.encoding.reg_encode:
            raise ValueError(f"Unknown register: {name}")
        return self.encoding.reg_encode[key]

    def reg_name(self, value: int) -> str:
        if value == 0:
            return "NONE"
        return self.encoding.reg_decode.get(value, f"0x{value:02x}")

    def parse_imm(self, token: str) -> int:
        value = int(token, 0)
        if not 0 <= value <= 0xFF:
            raise ValueError(f"Immediate out of byte range: {token}")
        return value

    def parse_flags(self, token: str) -> int:
        clean = token.strip().upper()
        if clean == "*":
            return 0
        bits = 0
        for ch in clean:
            if ch not in self.encoding.flag_encode or ch == "*":
                raise ValueError(f"Unknown flag char: {ch}")
            bits |= self.encoding.flag_encode[ch]
        return bits

    def describe_flags(self, value: int) -> str:
        if value == 0:
            return "*"
        names = [name for name in CANONICAL_FLAGS if value & self.encoding.flag_encode.get(name, 0)]
        return "".join(names) if names else f"0x{value:02x}"

    def parse_sys_mask(self, token: str) -> int:
        text = token.strip()
        if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", text):
            return self.parse_imm(text)

        bits = 0
        for part in re.split(r"[|+]", text):
            name = part.strip().upper()
            if not name:
                continue
            if name not in self.encoding.sys_encode:
                raise ValueError(f"Unknown syscall bit: {name}")
            bits |= self.encoding.sys_encode[name]
        return bits

    def describe_sys_mask(self, value: int) -> str:
        if value == 0:
            return "0x00"

        names = [
            name for name in CANONICAL_SYSCALLS if value & self.encoding.sys_encode.get(name, 0)
        ]
        if names:
            return "|".join(names)
        return f"0x{value:02x}"

    def active_instruction_names(self, opcode: int) -> list[str]:
        names: list[str] = []
        for name in CANONICAL_INSTRUCTIONS:
            bit = self.encoding.opcode_encode.get(name)
            if bit is None:
                continue
            if opcode & bit:
                names.append(name)
        return names

    def assemble_line(self, line: str) -> tuple[int, int, int]:
        text = line.strip()
        if not text:
            raise ValueError("Empty instruction")

        if m := self._IMM_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["IMM"],
                self.reg_value(m.group(1)),
                self.parse_imm(m.group(2)),
            )

        if m := self._ADD_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["ADD"],
                self.reg_value(m.group(1)),
                self.reg_value(m.group(2)),
            )

        if m := self._STK_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["STK"],
                self.reg_value(m.group(1)),
                self.reg_value(m.group(2)),
            )

        if m := self._STM_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["STM"],
                self.reg_value(m.group(1)),
                self.reg_value(m.group(2)),
            )

        if m := self._LDM_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["LDM"],
                self.reg_value(m.group(1)),
                self.reg_value(m.group(2)),
            )

        if m := self._CMP_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["CMP"],
                self.reg_value(m.group(1)),
                self.reg_value(m.group(2)),
            )

        if m := self._JMP_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["JMP"],
                self.parse_flags(m.group(1)),
                self.reg_value(m.group(2)),
            )

        if m := self._SYS_RE.fullmatch(text):
            return (
                self.encoding.opcode_encode["SYS"],
                self.parse_sys_mask(m.group(1)),
                self.reg_value(m.group(2)),
            )

        raise ValueError(f"Cannot parse instruction: {line}")

    def format_instruction(self, opcode: int, arg1: int, arg2: int) -> str:
        names = self.active_instruction_names(opcode)
        if not names:
            return f"??? op={opcode:#04x} arg1={arg1:#04x} arg2={arg2:#04x}"

        lines: list[str] = []
        for name in names:
            if name == "IMM":
                lines.append(f"IMM {self.reg_name(arg1)} = {arg2:#04x}")
            elif name == "ADD":
                lines.append(f"ADD {self.reg_name(arg1)} {self.reg_name(arg2)}")
            elif name == "STK":
                lines.append(f"STK {self.reg_name(arg1)} {self.reg_name(arg2)}")
            elif name == "STM":
                lines.append(f"STM *{self.reg_name(arg1)} = {self.reg_name(arg2)}")
            elif name == "LDM":
                lines.append(f"LDM {self.reg_name(arg1)} = *{self.reg_name(arg2)}")
            elif name == "CMP":
                lines.append(f"CMP {self.reg_name(arg1)} {self.reg_name(arg2)}")
            elif name == "JMP":
                lines.append(f"JMP {self.describe_flags(arg1)} {self.reg_name(arg2)}")
            elif name == "SYS":
                lines.append(f"SYS {self.describe_sys_mask(arg1)} {self.reg_name(arg2)}")

        return " ; ".join(lines)

    def assemble(self, asm_text: str) -> bytes:
        out = bytearray()
        for raw in asm_text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            opcode, arg1, arg2 = self.assemble_line(line)
            out.extend(self.encode_instruction_bytes(opcode, arg1, arg2))
        return bytes(out)

    def disassemble(self, data: bytes) -> list[str]:
        lines: list[str] = []
        for offset in range(0, len(data), 3):
            if offset + 2 >= len(data):
                break
            opcode, arg1, arg2 = self.decode_instruction_bytes(data[offset : offset + 3])
            lines.append(f"{offset:#06x}: {self.format_instruction(opcode, arg1, arg2)}")
        return lines
