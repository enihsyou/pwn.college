import unittest
from collections.abc import Generator
from itertools import islice

from dojotool import aslr


class AslrTests(unittest.TestCase):
    def test_returns_generator(self) -> None:
        result = aslr(0x1000, 12)
        self.assertIsInstance(result, Generator)
        # Generators are lazy: nothing has been produced yet.
        self.assertEqual(list(islice(result, 0)), [])

    def test_generator_is_stateful(self) -> None:
        gen = aslr(0x1000, 12)
        # First slice yields the lowest 4 candidates.
        self.assertEqual(list(islice(gen, 4)), [0x000, 0x1000, 0x2000, 0x3000])
        # State is preserved: the next slice yields candidates 4-8.
        self.assertEqual(list(islice(gen, 4)), [0x4000, 0x5000, 0x6000, 0x7000])
        # Exhausting the remaining 8 then querying again yields nothing further.
        self.assertEqual(len(list(gen)), 8)
        self.assertEqual(list(gen), [])

    def test_default_bits_is_12(self) -> None:
        self.assertEqual(list(aslr(0x123456789ABC)), list(aslr(0x123456789ABC, 12)))

    def test_userspace_pages_12_bits(self) -> None:
        # Result width is 16 bits, so high bits of addr are truncated.
        # fixed_part = 0x123456789abc & 0xfff = 0xabc.
        self.assertEqual(
            list(aslr(0x123456789ABC, 12)),
            [
                0xABC,
                0x1ABC,
                0x2ABC,
                0x3ABC,
                0x4ABC,
                0x5ABC,
                0x6ABC,
                0x7ABC,
                0x8ABC,
                0x9ABC,
                0xAABC,
                0xBABC,
                0xCABC,
                0xDABC,
                0xEABC,
                0xFABC,
            ],
        )

    def test_kernel_pages_21_bits(self) -> None:
        # Result width is 24 bits. fixed_part = 0x123456789abc & 0x1fffff = 0x189abc.
        self.assertEqual(
            list(aslr(0x123456789ABC, 21)),
            [
                0x189ABC,
                0x389ABC,
                0x589ABC,
                0x789ABC,
                0x989ABC,
                0xB89ABC,
                0xD89ABC,
                0xF89ABC,
            ],
        )

    def test_byte_aligned_bits_yield_single_value(self) -> None:
        # bits==8: result width 8 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x123456789ABC, 8)), [0xBC])
        # bits==16: result width 16 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x123456789ABC, 16)), [0x9ABC])
        # bits==24: result width 24 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x123456789ABC, 24)), [0x789ABC])
        # bits==32: result width 32 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x12345678, 32)), [0x12345678])

    def test_sub_byte_bits_enumerate_to_next_byte(self) -> None:
        self.assertEqual(
            list(aslr(0xABC, 4)),
            [
                0xC,
                0x1C,
                0x2C,
                0x3C,
                0x4C,
                0x5C,
                0x6C,
                0x7C,
                0x8C,
                0x9C,
                0xAC,
                0xBC,
                0xCC,
                0xDC,
                0xEC,
                0xFC,
            ],
        )

    def test_count_matches_byte_boundary_gap(self) -> None:
        # Number of candidates = 2^(rounded_byte_boundary - bits).
        cases = [
            (12, 1 << 4),  # 16 bits wide -> 16 candidates
            (21, 1 << 3),  # 24 bits wide -> 8 candidates
            (20, 1 << 4),  # 24 bits wide -> 16 candidates
            (8, 1),  # 8 bits wide  -> 1 candidate
            (16, 1),  # 16 bits wide -> 1 candidate
            (4, 1 << 4),  # 8 bits wide  -> 16 candidates
            (1, 1 << 7),  # 8 bits wide  -> 128 candidates
        ]
        for bits, expected in cases:
            with self.subTest(bits=bits):
                self.assertEqual(len(list(aslr(0x123456789ABC, bits))), expected)

    def test_preserves_lowest_bits(self) -> None:
        addr = 0xDEADBEEFCAFEF00D
        for bits in (1, 4, 8, 12, 13, 16, 20, 21, 24, 32):
            with self.subTest(bits=bits):
                mask = (1 << bits) - 1
                expected_low = addr & mask
                for value in aslr(addr, bits):
                    self.assertEqual(value & mask, expected_low)

    def test_values_are_unique(self) -> None:
        for bits in (12, 21, 20, 4, 1):
            with self.subTest(bits=bits):
                values = list(aslr(0x123456789ABC, bits))
                self.assertEqual(len(values), len(set(values)))

    def test_values_fit_in_result_byte_width(self) -> None:
        # Every candidate must fit within the rounded-up byte boundary.
        for bits in (12, 21, 20, 4, 1):
            with self.subTest(bits=bits):
                result_bits = ((bits + 7) // 8) * 8
                mask = (1 << result_bits) - 1
                for value in aslr(0x123456789ABCDEF0, bits):
                    self.assertEqual(value & ~mask, 0)

    def test_addr_must_be_positive(self) -> None:
        with self.assertRaises(AssertionError):
            list(aslr(0, 12))
        with self.assertRaises(AssertionError):
            list(aslr(-1, 12))

    def test_bits_must_be_positive(self) -> None:
        with self.assertRaises(AssertionError):
            list(aslr(0x1000, 0))
        with self.assertRaises(AssertionError):
            list(aslr(0x1000, -5))
