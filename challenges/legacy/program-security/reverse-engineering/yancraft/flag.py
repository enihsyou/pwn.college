# Yancraft
from yan85_asm import assemble
import pwn

pwn.context.os = "linux"
pwn.context.arch = "amd64"


def tee[T: pwn.tube](process: T) -> T:
    import sys

    orig_recv_raw = process.recv_raw
    output = sys.__stdout__.buffer  # type: ignore sys.stdout is replaced by pwn.term

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
        output.write(data)
        output.flush()
        return data

    process.recv_raw = recv_raw
    return process


# Hardcoded Yan85 assembly input.
asm_code = """
# Write '/flag\0' to memory starting at 0x80 using IMM + STM
IMM a = 0x80
IMM b = 0x2f
STM *a = b
IMM a = 0x81
IMM b = 0x66
STM *a = b
IMM a = 0x82
IMM b = 0x6c
STM *a = b
IMM a = 0x83
IMM b = 0x61
STM *a = b
IMM a = 0x84
IMM b = 0x67
STM *a = b
IMM a = 0x85
IMM b = 0x00
STM *a = b

# open('/flag', 0, 0) -> fd in d
IMM a = 0x80
IMM b = 0x00
IMM c = 0x00
SYS 0x01 d

# read(fd, 0x90, 0xff)
STK a d
IMM b = 0x90
IMM c = 0xff
SYS 0x10 d

# write(1, 0x90, 0xff)
IMM a = 0x01
IMM b = 0x90
IMM c = 0xff
SYS 0x02 d

# exit(0)
IMM a = 0x00
SYS 0x20 NONE
"""

bytecode = assemble(asm_code)
print(bytecode.hex())

with pwn.process("/challenge/*", shell=True, raw=True) as io:
    io = tee(io)
    io.sendline(bytecode)
    io.sendline()
    io.recvrepeat()
