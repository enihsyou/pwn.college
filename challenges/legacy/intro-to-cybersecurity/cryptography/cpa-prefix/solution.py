from pwn import process, log


def ctf():
    p = process('/challenge/run')
    BLOCK_SIZE = 16

    def send_data(choice: bytes, payload: bytes) -> bytes:
        p.sendlineafter(b'Choice?', choice)
        p.sendlineafter(b'Data?', payload)
        result = p.recvline_contains(b'Result:').decode()
        result = result.split(':')[1].strip()
        return bytes.fromhex(result)

    with log.progress('Recovering Flag') as progress:
        flag = b''
        guess_idx = 0

        while True:
            pad_len = BLOCK_SIZE - 1 - (guess_idx % BLOCK_SIZE)
            pad_data = b'A' * pad_len

            cipher_opt2 = send_data(b'2', pad_data)

            target_block_idx = guess_idx // BLOCK_SIZE
            start_idx = target_block_idx * BLOCK_SIZE

            # Handle edge case: if start_idx is out of bounds, we've exhausted the ciphertext
            if start_idx >= len(cipher_opt2):
                break

            target_block = cipher_opt2[start_idx: start_idx + BLOCK_SIZE]
            known_prefix = (pad_data + flag)[-BLOCK_SIZE+1:]

            found = False
            for c in range(0x20, 0x80):
                guess_char = bytes([c])
                guess_payload = known_prefix + guess_char
                if not guess_char.strip():
                    # Program won't let us input whitespace character
                    continue

                cipher_opt1 = send_data(b'1', guess_payload)
                guess_block = cipher_opt1[:BLOCK_SIZE]

                if guess_block == target_block:
                    flag += guess_char
                    progress.status(f'Recovered so far: {flag.decode()}')
                    found = True
                    break

            if not found:
                log.error(f'Failed to recover byte at index {guess_idx}.')
                break

            if guess_char == b'}':
                log.info("Reached end of flag format '}'. Terminating.")
                break

            guess_idx += 1

        log.success(f'Flag: {flag.decode()}')


if __name__ == "__main__":
    ctf()
