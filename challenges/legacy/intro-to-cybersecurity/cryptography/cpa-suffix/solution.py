from pwn import process, log
from string import printable, whitespace


def ctf():
    p = process('/challenge/run')
    with log.progress('Recovering Flag') as progress:
        flags = []
        for i in range(1, 61):
            progress.status(f'Capture {''.join(reversed(flags))}')
            p.sendlineafter(b'Choice?', b'2')
            p.sendlineafter(b'Length?', str(i).encode())
            result = p.recvline_contains(b'Result:')
            result = result.split(b':')[1].strip()

            for c in printable:
                if c in whitespace:
                    continue
                trying = ''.join(reversed(flags + [c]))
                progress.status(f'Testing {trying}')
                p.sendlineafter(b'Choice?', b'1')
                p.sendlineafter(b'Data?', trying.encode())
                cipher = p.recvline_contains(b'Result:')
                cipher = cipher.split(b':')[1].strip()
                if cipher == result:
                    flags = flags + [c]
                    break

    log.success('Flag: %s', ''.join(reversed(flags)))


if __name__ == "__main__":
    ctf()
