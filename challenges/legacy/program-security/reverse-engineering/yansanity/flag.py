# Yansanity
from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass

import pwn
from yan85_vm import Yan85Encoding, Yan85VM

pwn.context.os = "linux"
pwn.context.arch = "amd64"
pwn.context.log_level = "info"

BITS = [1 << i for i in range(8)]
FLAG_RE = re.compile(rb"pwn\.college\{[^\n\r]+\}")


@dataclass(frozen=True)
class ProbeResult:
    exit_code: int | None
    blocked_before_followup: bool
    blocked: bool
    output: bytes


class ProcessOracle:
    def __init__(self, challenge_path) -> None:
        self.challenge_path = challenge_path

    def _spawn(self) -> pwn.process:
        io = pwn.process(self.challenge_path, raw=True)
        io.recvuntil(b"yancode: ", timeout=3)
        return io

    def run_once(
        self,
        yancode: bytes,
        followup: bytes | None = None,
        settle: float = 0.25,
    ) -> ProbeResult:
        print(pwn.hexdump(yancode, total=False))

        with pwn.context.silent:
            io = self._spawn()

            def recv():
                try:
                    return io.recv(4096, settle)
                except EOFError:
                    return b""

            try:
                io.send(yancode)
                pwn.sleep(settle)
                status = io.poll(block=False)
                blocked_before_followup = status is None

                if blocked_before_followup and followup:
                    io.send(followup)
                    pwn.sleep(settle)
                    status = io.poll(block=False)

                output = recv() + recv()
                blocked = status is None
                if blocked:
                    pwn.process(["kill", "-9", str(io.pid)]).wait()

                return ProbeResult(
                    exit_code=status,
                    blocked_before_followup=blocked_before_followup,
                    blocked=blocked,
                    output=output,
                )
            finally:
                io.close()


def make_probe_vm(encoding_setup) -> Yan85VM:
    vm = Yan85VM(Yan85Encoding(encoding_setup))
    vm.encoding.set_register_encoding("none", 0)
    vm.encoding.set_flag_encoding("*", 0)
    return vm


@contextmanager
def _probing_opcode(vm: Yan85VM, name: str, value: int):
    vm.encoding.set_opcode_encoding(name, value)
    try:
        yield
    finally:
        vm.encoding.opcode_encode.pop(name.upper(), None)


@contextmanager
def _probing_register(vm: Yan85VM, name: str, value: int):
    vm.encoding.set_register_encoding(name, value)
    try:
        yield
    finally:
        vm.encoding.reg_encode.pop(name.lower(), None)


@contextmanager
def _probing_syscall(vm: Yan85VM, name: str, value: int):
    vm.encoding.set_syscall_encoding(name, value)
    try:
        yield
    finally:
        vm.encoding.sys_encode.pop(name.upper(), None)


def find_sys_opcode_and_exit_bit(oracle: ProcessOracle, vm: Yan85VM) -> tuple[int, int]:
    for op in BITS:
        with _probing_opcode(vm, "SYS", op):
            for sys_bit in BITS:
                with _probing_syscall(vm, "EXIT", sys_bit):
                    payload = vm.assemble(
                        """
                        SYS EXIT NONE
                        """
                    )
                    result = oracle.run_once(payload)
                    if result.exit_code == 0:
                        return op, sys_bit
    raise RuntimeError("Could not discover SYS opcode + SYS_EXIT bit")


def find_imm_opcode_and_reg_a(oracle: ProcessOracle, vm: Yan85VM) -> tuple[int, int]:
    for imm_op in BITS:
        with _probing_opcode(vm, "IMM", imm_op):
            for reg in BITS:
                with _probing_register(vm, "a", reg):
                    payload = vm.assemble(
                        """
                        IMM a = 0x5A
                        SYS EXIT NONE
                        """
                    )
                    result = oracle.run_once(payload)
                    if result.exit_code == 0x5A:
                        return imm_op, reg
    raise RuntimeError("Could not discover IMM opcode + register a")


def find_read_memory_and_regs_c(oracle: ProcessOracle, vm: Yan85VM) -> tuple[int, int]:
    for sys_bit in BITS:
        if sys_bit in vm.encoding.sys_decode:
            continue
        sys_bit = 0x04
        with _probing_syscall(vm, "READ_MEMORY", sys_bit):
            for reg_c in BITS:
                if reg_c in vm.encoding.reg_decode:
                    continue
                with _probing_register(vm, "c", reg_c):
                    payload = vm.assemble(
                        """
                        IMM a = 0x00
                        IMM c = 0x02
                        SYS READ_MEMORY a
                        SYS EXIT NONE
                        """
                    )
                    result = oracle.run_once(payload, followup=b"\x01\x02\x03\x04")
                    if result.blocked_before_followup and result.exit_code == 2:
                        return sys_bit, reg_c

    raise RuntimeError("Could not discover SYS_READ_MEMORY and registers c")


def find_sys_write_bit(oracle: ProcessOracle, vm: Yan85VM) -> int:
    sentinel = b"\x01\x02"
    for sys_bit in BITS:
        if sys_bit in vm.encoding.sys_decode:
            continue
        with _probing_syscall(vm, "WRITE", sys_bit):
            payload = b"\0" * 30 + vm.assemble(
                """
                IMM a = 0x00
                IMM c = 0x02
                SYS READ_MEMORY a
                IMM a = 0x01
                IMM c = 0x02
                SYS WRITE a
                SYS EXIT NONE
                """
            )
            result = oracle.run_once(payload, followup=sentinel)
            if (
                result.blocked_before_followup
                and result.exit_code == 2
                and sentinel in result.output
            ):
                return sys_bit

    raise RuntimeError("Could not discover SYS_WRITE bit")


def find_sys_open_bit(oracle: ProcessOracle, vm: Yan85VM) -> int:
    for sys_open_bit in BITS:
        if sys_open_bit in vm.encoding.sys_decode:
            continue
        with _probing_syscall(vm, "OPEN", sys_open_bit):
            # OPEN on empty-path pointer should fail with -1 (0xff), while other
            # syscalls with len=0 and a=0 generally return 0 and do not match.
            payload = vm.assemble(
                """
                SYS OPEN a
                SYS EXIT NONE
                """
            )
            result = oracle.run_once(payload)
            if result.exit_code == 0xFF:
                return sys_open_bit

    raise RuntimeError("Could not discover SYS_OPEN bit")


def discover_encoding(oracle: ProcessOracle, encoding_setup):
    vm = make_probe_vm(encoding_setup)

    sys_op, sys_exit_bit = find_sys_opcode_and_exit_bit(oracle, vm)
    vm.encoding.set_opcode_encoding("SYS", sys_op)
    vm.encoding.set_syscall_encoding("EXIT", sys_exit_bit)
    pwn.success(f"SYS opcode=0x{sys_op:02x}, EXIT bit=0x{sys_exit_bit:02x}")

    imm_op, reg_a = find_imm_opcode_and_reg_a(oracle, vm)
    vm.encoding.set_opcode_encoding("IMM", imm_op)
    vm.encoding.set_register_encoding("a", reg_a)
    pwn.success(f"IMM opcode=0x{imm_op:02x}, reg_a=0x{reg_a:02x}")

    sys_read_memory_bit, reg_c = find_read_memory_and_regs_c(oracle, vm)
    vm.encoding.set_syscall_encoding("READ_MEMORY", sys_read_memory_bit)
    vm.encoding.set_register_encoding("c", reg_c)
    pwn.success(f"READ_MEMORY bit=0x{sys_read_memory_bit:02x}, reg_c=0x{reg_c:02x}")

    sys_write_bit = find_sys_write_bit(oracle, vm)
    vm.encoding.set_syscall_encoding("WRITE", sys_write_bit)
    pwn.success(f"WRITE bit=0x{sys_write_bit:02x}")

    sys_open_bit = find_sys_open_bit(oracle, vm)
    vm.encoding.set_syscall_encoding("OPEN", sys_open_bit)
    pwn.success(f"OPEN bit=0x{sys_open_bit:02x}")

    return vm.encoding


def build_flag_payload(vm: Yan85VM) -> bytes:
    asm = """
    IMM a = 0x00
    IMM c = 0x06
    SYS READ_MEMORY a

    IMM a = 0x00
    SYS OPEN a

    IMM c = 0xff
    SYS READ_MEMORY c

    IMM a = 0x01
    SYS WRITE NONE

    IMM a = 0x00
    SYS EXIT NONE
    """
    return b"\0" * 30 + vm.assemble(asm)


def exploit_once(oracle: ProcessOracle, vm: Yan85VM) -> str:
    payload = build_flag_payload(vm)
    result = oracle.run_once(payload, followup=b"/flag\x00")
    match = FLAG_RE.search(result.output)
    if not match:
        text = result.output.decode("utf-8", errors="replace")
        raise RuntimeError(f"Flag not found in output: {text}")
    return match.group(0).decode()


def run() -> None:
    # oracle = ProcessOracle("/challenge/yansanity-easy")
    # encoding = ("arg2", "arg1", "opcode")
    oracle = ProcessOracle("/challenge/yansanity-hard")
    encoding = ("opcode", "arg1", "arg2")
    encoding = discover_encoding(oracle, encoding)
    flag = exploit_once(oracle, Yan85VM(encoding))
    pwn.success(flag)


if __name__ == "__main__":
    run()
