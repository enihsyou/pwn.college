from pwn import process, log


def ctf():
    p = process('/challenge/run')
    BLOCK_SIZE = 16

    def send_data(payload: bytes) -> bytes:
        p.sendlineafter(b'Choice?', b'2')
        p.sendlineafter(b'Data?', payload)
        result = p.recvline_contains(b'Result:').decode()
        result = result.split(':')[1].strip()
        return bytes.fromhex(result)

    with log.progress('Recovering Flag') as progress:
        flag = b''
        guess_idx = 0
        guess_len = 1
        charset = [bytes([c]) for c in range(0x21, 0x7f)]

        while True:
            pad_len = BLOCK_SIZE - (guess_idx % BLOCK_SIZE) - guess_len
            pad_data = b'.' * pad_len

            target_cipher = send_data(pad_data)
            target_start = (guess_idx // BLOCK_SIZE) * BLOCK_SIZE
            target_block = target_cipher[target_start:target_start+BLOCK_SIZE]

            known_prefix = (pad_data + flag)[-BLOCK_SIZE+guess_len:]
            guess_payload = b''.join(known_prefix + c for c in charset)

            guess_cipher = send_data(guess_payload)
            for i, guess_char in enumerate(charset):
                char_start = i*BLOCK_SIZE
                char_block = guess_cipher[char_start:char_start+BLOCK_SIZE]
                if char_block == target_block:
                    flag += guess_char
                    progress.status(flag.decode())
                    break
            else:
                progress.success(f"Algorithm halts at index {guess_idx}")
                break

            guess_idx += 1

        log.success(f'Flag: {flag.decode()}')


if __name__ == "__main__":
    ctf()
