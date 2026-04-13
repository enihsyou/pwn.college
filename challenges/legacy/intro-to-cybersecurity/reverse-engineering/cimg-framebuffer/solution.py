from pwn import args, process, read, write
import struct
import re


LEN_COLOR_ESC = 24
ESCAPED_PIXEL = re.compile(
    rb"\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m", re.DOTALL)
DEFAULT_FILE = "answer.cimg"
DEFAULT_SOURCE = "desired_output.bin"


# dump with two steps
# objdump -t /challenge/cimg | grep desired_output
# gdb -batch -ex "dump memory desired_output.bin 0x404020 (0x404020 + 0x6db2)" /challenge/cimg
def load_raw_input(source_path: str) -> bytes:
    return read(source_path)


def parse_pixels(raw_input: bytes):
    w1 = raw_input.index(b'.', 0)
    w2 = raw_input.index(b'.', w1 + 1)
    width = (w2 - w1) // LEN_COLOR_ESC + 1
    height = len(raw_input) // (width * LEN_COLOR_ESC)

    matches = list(ESCAPED_PIXEL.finditer(raw_input))
    expected = width * height
    if len(matches) != expected:
        raise ValueError(f"parsed {len(matches)} pixels, expected {expected}")

    pixels = bytearray()
    for match in matches:
        r, g, b, char = match.groups()
        pixels += struct.pack("<BBBB", int(r), int(g), int(b), char[0])

    return width, height, bytes(pixels)


def build_payload(raw_input: bytes) -> bytes:
    width, height, pixels = parse_pixels(raw_input)

    header = struct.pack("<4sHBBI", b"cIMG", 3, width, height, 1)
    directive = struct.pack("<H", 6331)
    return header + directive + pixels


def main():
    source_path = args.SOURCE or DEFAULT_SOURCE
    file_path = args.FILE or DEFAULT_FILE
    chall_path = args.CHALL or "/challenge/cimg"

    raw_input = load_raw_input(source_path)
    payload = build_payload(raw_input)
    write(file_path, payload)

    if args.NO_RUN:
        return

    io = process([chall_path, file_path])
    print(io.clean().decode(errors='ignore'))
    if io.poll() is None:
        io.interactive()


if __name__ == "__main__":
    main()
