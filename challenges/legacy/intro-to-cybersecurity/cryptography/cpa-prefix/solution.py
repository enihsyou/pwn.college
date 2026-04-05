from pwn import process, log
from string import printable


def ctf():
    p = process('/challenge/run')
    BLOCK_SIZE = 16

    def send_data(choice, payload):
        p.sendlineafter(b'Choice?', choice)
        p.sendlineafter(b'Data?', payload)
        result = p.recvline_contains(b'Result:').decode()
        result = result.split(':')[1].strip()
        return bytes.fromhex(result)

    with log.progress('Calculating flag length') as progress:
        # Get the base ciphertext length with no prepend
        base_cipher = send_data(b'2', b'')
        base_len = len(base_cipher)

        jump_pad_len = 0
        for size in range(1, BLOCK_SIZE + 1):
            progress.status(f'Testing pad length {size}')
            cipher = send_data(b'2', b'A' * size)
            if len(cipher) > base_len:
                jump_pad_len = size
                break

        flag_length = base_len - jump_pad_len + 1
        progress.success(f'Flag length: {flag_length}')

    with log.progress('Recovering Flag') as progress:
        flag = b''
        for i in range(flag_length):
            pad_len = 15 - (i % BLOCK_SIZE)
            pad_data = b'A' * pad_len

            cipher_opt2 = send_data(b'2', pad_data)

            target_block_idx = i // BLOCK_SIZE
            start_idx = target_block_idx * BLOCK_SIZE
            target_block = cipher_opt2[start_idx: start_idx + BLOCK_SIZE]

            known_prefix = (pad_data + flag)[-15:]

            found = False
            for c in printable.encode():
                guess_char = bytes([c])
                guess_payload = known_prefix + guess_char

                cipher_opt1 = send_data(b'1', guess_payload)
                guess_block = cipher_opt1[:BLOCK_SIZE]

                if guess_block == target_block:
                    flag += guess_char
                    progress.status(f'Recovered so far: {flag.decode()}')
                    found = True
                    break

            if not found:
                progress.failure(f'Failed to recover byte at index {i}')
                break

        log.success(f'Flag: {flag.decode()}')


if __name__ == "__main__":
    ctf()
