from pwn import process, log, context, run_in_new_terminal
from string import printable, whitespace


def tee(process, logfile='/tmp/challenge.log'):
    orig_send_raw = process.send_raw
    orig_recv_raw = process.recv_raw
    log_file = open(logfile, 'wb')

    def send_raw(data):
        log_file.write(data)
        log_file.flush()
        return orig_send_raw(data)

    def recv_raw(numb):
        data = orig_recv_raw(numb) or b''  # orig may return str('')
        log_file.write(data)
        log_file.flush()
        return data

    process.send_raw = send_raw
    process.recv_raw = recv_raw
    context.terminal = ['tmux', 'splitw', '-v']
    run_in_new_terminal('tail -s 0.1 -f ' + logfile, kill_at_exit=False)


def ctf():
    p = process('/challenge/run')
    tee(p, '/tmp/challenge.log')
    m = {}
    with log.progress('Mapping characters') as progress:
        for c in printable:
            if c in whitespace:
                continue
            progress.status(f'Mapping {c}')
            p.sendlineafter(b'Choice?', b'1')
            p.sendlineafter(b'Data?', c.encode())
            result = p.recvline_contains(b'Result:')
            result = result.split(b':')[1].strip()
            m[result] = c
    f = []
    with log.progress('Capture the flags') as progress:
        for i in range(64):
            progress.status(f'Capture #{i}')
            p.sendlineafter(b'Choice?', b'2')
            p.sendlineafter(b'Index?', str(i).encode())
            p.sendlineafter(b'Length?', b'1')
            result = p.recvline_contains(b'Result:')
            result = result.split(b':')[1].strip()
            if result in m:
                f.append(m[result])
    log.success('Flag: %s', ''.join(f))


if __name__ == "__main__":
    ctf()
