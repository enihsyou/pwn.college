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
        self.assertEqual(list(aslr(0x123456789abc)), list(aslr(0x123456789abc, 12)))

    def test_userspace_pages_12_bits(self) -> None:
        # Result width is 16 bits, so high bits of addr are truncated.
        # fixed_part = 0x123456789abc & 0xfff = 0xabc.
        self.assertEqual(
            list(aslr(0x123456789abc, 12)),
            [
                0xabc, 0x1abc, 0x2abc, 0x3abc,
                0x4abc, 0x5abc, 0x6abc, 0x7abc,
                0x8abc, 0x9abc, 0xaabc, 0xbabc,
                0xcabc, 0xdabc, 0xeabc, 0xfabc,
            ],
        )

    def test_kernel_pages_21_bits(self) -> None:
        # Result width is 24 bits. fixed_part = 0x123456789abc & 0x1fffff = 0x189abc.
        self.assertEqual(
            list(aslr(0x123456789abc, 21)),
            [
                0x189abc, 0x389abc, 0x589abc, 0x789abc,
                0x989abc, 0xb89abc, 0xd89abc, 0xf89abc,
            ],
        )

    def test_byte_aligned_bits_yield_single_value(self) -> None:
        # bits==8: result width 8 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x123456789abc, 8)), [0xbc])
        # bits==16: result width 16 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x123456789abc, 16)), [0x9abc])
        # bits==24: result width 24 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x123456789abc, 24)), [0x789abc])
        # bits==32: result width 32 bits, no enumeration bits remain.
        self.assertEqual(list(aslr(0x12345678, 32)), [0x12345678])

    def test_sub_byte_bits_enumerate_to_next_byte(self) -> None:
        self.assertEqual(
            list(aslr(0xabc, 4)),
            [0xc, 0x1c, 0x2c, 0x3c, 0x4c, 0x5c, 0x6c, 0x7c,
             0x8c, 0x9c, 0xac, 0xbc, 0xcc, 0xdc, 0xec, 0xfc],
        )

    def test_count_matches_byte_boundary_gap(self) -> None:
        # Number of candidates = 2^(rounded_byte_boundary - bits).
        cases = [
            (12, 1 << 4),  # 16 bits wide -> 16 candidates
            (21, 1 << 3),  # 24 bits wide -> 8 candidates
            (20, 1 << 4),  # 24 bits wide -> 16 candidates
            (8, 1),        # 8 bits wide  -> 1 candidate
            (16, 1),       # 16 bits wide -> 1 candidate
            (4, 1 << 4),   # 8 bits wide  -> 16 candidates
            (1, 1 << 7),   # 8 bits wide  -> 128 candidates
        ]
        for bits, expected in cases:
            with self.subTest(bits=bits):
                self.assertEqual(len(list(aslr(0x123456789abc, bits))), expected)

    def test_preserves_lowest_bits(self) -> None:
        addr = 0xdeadbeefcafef00d
        for bits in (1, 4, 8, 12, 13, 16, 20, 21, 24, 32):
            with self.subTest(bits=bits):
                mask = (1 << bits) - 1
                expected_low = addr & mask
                for value in aslr(addr, bits):
                    self.assertEqual(value & mask, expected_low)

    def test_values_are_unique(self) -> None:
        for bits in (12, 21, 20, 4, 1):
            with self.subTest(bits=bits):
                values = list(aslr(0x123456789abc, bits))
                self.assertEqual(len(values), len(set(values)))

    def test_values_fit_in_result_byte_width(self) -> None:
        # Every candidate must fit within the rounded-up byte boundary.
        for bits in (12, 21, 20, 4, 1):
            with self.subTest(bits=bits):
                result_bits = ((bits + 7) // 8) * 8
                mask = (1 << result_bits) - 1
                for value in aslr(0x123456789abcdef0, bits):
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
