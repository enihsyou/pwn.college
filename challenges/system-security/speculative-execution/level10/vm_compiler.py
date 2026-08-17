# 在 C 里不好写这个 VM，直接调用 Python
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


def compile() -> None:
    offset = 0x00
    pos = int(sys.argv[1])
    bytecode = f"""
    # write /flag to memory 0x00
    IMM a = {hex(offset)}
    IMM b = {hex(ord("/"))}
    STM *a = b
    IMM a = {hex(offset + 1)}
    IMM b = {hex(ord("f"))}
    STM *a = b
    IMM a = {hex(offset + 2)}
    IMM b = {hex(ord("l"))}
    STM *a = b
    IMM a = {hex(offset + 3)}
    IMM b = {hex(ord("a"))}
    STM *a = b
    IMM a = {hex(offset + 4)}
    IMM b = {hex(ord("g"))}
    STM *a = b
    IMM a = {hex(offset + 5)}
    IMM b = {hex(ord("\0"))}
    STM *a = b

    # open("/flag", 0x00) = fd(a)
    IMM a = 0x00
    IMM b = 0x00
    SYS OPEN a
    # read(fd(a), 0x80, 0x40)
    IMM b = 0x80
    IMM c = 0x40
    SYS READ a

    IMM a = {hex(0x80 + pos)}
    SYS EXEC|EXIT a
    """

    vm = Yan85VM()
    setting_vm(vm)
    bytecode = vm.assemble(bytecode)
    sys.stdout.buffer.write(bytecode)
    sys.stdout.buffer.flush()

if __name__ == "__main__":
    raise SystemExit(compile())
