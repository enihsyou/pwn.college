import unittest

from dojotool.yan85_vm import Yan85Encoding, Yan85VM


def configure_vm(vm: Yan85VM) -> Yan85VM:
    vm.encoding.set_instruction_layout(("opcode", "arg1", "arg2"))
    for name, value in {
        "SYS": 0x04,
        "LDM": 0x80,
        "STK": 0x40,
        "ADD": 0x01,
        "IMM": 0x20,
        "CMP": 0x02,
        "STM": 0x08,
        "JMP": 0x10,
    }.items():
        vm.encoding.set_opcode_encoding(name, value)
    for name, value in {
        "a": 0x20,
        "b": 0x40,
        "c": 0x08,
        "d": 0x02,
        "s": 0x04,
        "i": 0x01,
        "f": 0x10,
        "none": 0x00,
    }.items():
        vm.encoding.set_register_encoding(name, value)
    for name, value in {
        "L": 0x10,
        "G": 0x04,
        "E": 0x01,
        "N": 0x08,
        "Z": 0x02,
        "*": 0,
    }.items():
        vm.encoding.set_flag_encoding(name, value)
    for name, value in {
        "OPEN": 0x08,
        "READ": 0x20,
        "WRITE": 0x02,
        "EXEC": 0x40,
        "EXIT": 0x10,
    }.items():
        vm.encoding.set_syscall_encoding(name, value)
    return vm


def make_vm() -> Yan85VM:
    return configure_vm(Yan85VM())


class Yan85VMTests(unittest.TestCase):
    def test_assemble_then_disassemble_without_marker(self) -> None:
        source = """
        IMM a = 0x2a
        ADD a b
        STK none a
        STM *a = b
        LDM c = *d
        CMP a c
        JMP * i
        SYS OPEN a
        """
        vm = make_vm()
        bytecode = vm.assemble(source)
        self.assertEqual(
            vm.disassemble(bytecode, marker=False),
            [
                "IMM a = 0x2a",
                "ADD a b",
                "STK NONE a",
                "STM *a = b",
                "LDM c = *d",
                "CMP a c",
                "JMP * i",
                "SYS OPEN a",
            ],
        )
        self.assertEqual(vm.assemble("\n".join(vm.disassemble(bytecode, marker=False))), bytecode)

    def test_disassemble_marker_includes_offset(self) -> None:
        vm = make_vm()
        bytecode = vm.assemble("IMM a = 0x01\nADD a b")
        self.assertEqual(
            vm.disassemble(bytecode),
            [
                "0x0000: IMM a = 0x01",
                "0x0003: ADD a b",
            ],
        )
        self.assertEqual(
            vm.disassemble(bytecode, marker=False),
            [
                "IMM a = 0x01",
                "ADD a b",
            ],
        )

    def test_disassemble_marker_includes_jmp_index(self) -> None:
        vm = make_vm()
        bytecode = vm.assemble("IMM s = 0x01\nJMP E s")
        self.assertEqual(
            vm.disassemble(bytecode, marker=True),
            [
                "0x0000 [ 1]: IMM s = 0x01",
                "0x0003 [ 2]: JMP E s",
            ],
        )
        self.assertEqual(
            vm.disassemble(bytecode, marker=False),
            [
                "IMM s = 0x01",
                "JMP E s",
            ],
        )

    def test_comments_labels_and_combined_operands(self) -> None:
        source = """
        # write path then open/read
        start: IMM a = 0x00
        IMM b = [target]
        STM *a = b
        SYS OPEN|READ a
        JMP LE s
        target:
        SYS EXEC|EXIT a
        """
        vm = make_vm()
        bytecode = vm.assemble(source)
        listing = vm.disassemble(bytecode, marker=False)
        self.assertEqual(
            listing,
            [
                "IMM a = 0x00",
                "IMM b = 0x06",
                "STM *a = b",
                "SYS OPEN|READ a",
                "JMP LE s",
                "SYS EXEC|EXIT a",
            ],
        )
        self.assertEqual(vm.assemble("\n".join(listing)), bytecode)

    def test_instruction_layout_roundtrip(self) -> None:
        source = "IMM a = 0x7f\nSYS WRITE b"
        default_vm = make_vm()
        shuffled_vm = make_vm()
        shuffled_vm.encoding.set_instruction_layout(("arg2", "arg1", "opcode"))

        default_bytes = default_vm.assemble(source)
        shuffled_bytes = shuffled_vm.assemble(source)
        self.assertNotEqual(default_bytes, shuffled_bytes)
        self.assertEqual(default_vm.disassemble(default_bytes, marker=False), source.splitlines())
        self.assertEqual(shuffled_vm.disassemble(shuffled_bytes, marker=False), source.splitlines())
        self.assertEqual(shuffled_vm.assemble("\n".join(shuffled_vm.disassemble(shuffled_bytes, marker=False))), shuffled_bytes)

    def test_encoding_clone_and_layout_validation(self) -> None:
        vm = make_vm()
        clone = vm.encoding.clone()
        self.assertIsInstance(clone, Yan85Encoding)
        self.assertEqual(clone.opcode_encode, vm.encoding.opcode_encode)
        clone.set_opcode_encoding("IMM", 0x11)
        self.assertNotEqual(clone.opcode_encode["IMM"], vm.encoding.opcode_encode["IMM"])
        with self.assertRaises(ValueError):
            clone.set_instruction_layout(("opcode", "opcode", "arg1"))

    def test_assemble_rejects_unknown_instruction(self) -> None:
        vm = make_vm()
        with self.assertRaises(ValueError):
            vm.assemble("NOP a b")
        with self.assertRaises(ValueError):
            vm.assemble("loop:\nloop: IMM a = 0x00")
        with self.assertRaises(ValueError):
            vm.assemble("IMM a = [missing]")


if __name__ == "__main__":
    unittest.main()
