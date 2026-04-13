from pwn import process, write, read
import struct
import re

# dump with two steps
# objdump -t executable_file | grep desired_output
# gdb -batch -ex "dump memory desired_output.bin 0x404020 (0x404020 + 0x6db2)" /challenge/cimg
raw_input = read('desired_output.bin')

w1 = raw_input.index(b'.', 0)
w2 = raw_input.index(b'.', w1 + 1)
LEN_COLOR_ESC = 24
width = (w2 - w1) // LEN_COLOR_ESC + 1
height = len(raw_input) // (width * LEN_COLOR_ESC)

print(f"Width: {width}, Height: {height}")
l = LEN_COLOR_ESC * width
print(b'\n'.join([raw_input[i:i+l]
      for i in range(0, len(raw_input) // l * l, l)]).decode())

magic = b'cIMG'
version = 2
pixel = struct.Struct('<BBBB')
image_data = []
for match in re.finditer(rb'\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m', raw_input):
    r, g, b, char = match.groups()
    image_data.append(pixel.pack(int(r), int(g), int(b), ord(char)))

file_path = './a.cimg'
header = struct.pack('<4sHBB', magic, version, width, height)
write(file_path, header + b''.join(image_data))

io = process(['/challenge/cimg', file_path])
io.stream()
