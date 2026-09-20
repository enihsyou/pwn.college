from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final, cast

import gdb  # type: ignore[import-not-found]

ANSI_RESET: Final = "\x1b[0m"
ANSI_ESCAPE_RE: Final[re.Pattern[str]] = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

FRAME_UNAVAILABLE_MARKERS: Final = (
    "Cannot display stack frame",
    "The frame register is not defined for this architecture.",
)

_GDB_EXECUTE = cast(Callable[..., str | None], gdb.execute)


class PwndbgCommandWindow:
    def __init__(
        self,
        tui_window: gdb.TuiWindow,
        window_name: str,
        title: str,
        command: str,
        *,
        fallback_command: str | None = None,
        fallback_markers: tuple[str, ...] = (),
        fallback_title: str | None = None,
    ) -> None:
        self.win = tui_window
        self.window_name = window_name
        self.title = title
        self.command = command
        self.fallback_command = fallback_command
        self.fallback_markers = fallback_markers
        self.fallback_title = fallback_title or title

        self.lines: list[str] = []
        self.top = 0
        self.left = 0
        self.longest_line = 0

        self.win.title = self.title

        self._before_prompt_listener: Callable[[None], object] = self._before_prompt
        gdb.events.before_prompt.connect(self._before_prompt_listener)

        self.refresh(reset=True)

    def close(self) -> None:
        gdb.events.before_prompt.disconnect(self._before_prompt_listener)

    @staticmethod
    def _execute(command: str) -> str:
        try:
            try:
                output = _GDB_EXECUTE(
                    command,
                    False,
                    True,
                    True,
                )
            except TypeError:
                output = _GDB_EXECUTE(
                    command,
                    False,
                    True,
                )
        except gdb.error as exc:
            return f"\x1b[2m{exc}{ANSI_RESET}"

        return output or ""

    def _capture(self) -> str:
        output = self._execute(self.command)

        if self.fallback_command and any(marker in output for marker in self.fallback_markers):
            self.win.title = self.fallback_title
            return self._execute(self.fallback_command)

        self.win.title = self.title
        return output

    @staticmethod
    def _visible_length(line: str) -> int:
        return len(ANSI_ESCAPE_RE.sub("", line))

    @staticmethod
    def _ansi_slice(
        line: str,
        start: int,
        width: int,
    ) -> str:
        if width <= 0:
            return ""

        end = start + width
        visible_index = 0
        index = 0

        prefix: list[str] = []
        output: list[str] = []
        started = False

        while index < len(line):
            match = ANSI_ESCAPE_RE.match(line, index)

            if match is not None:
                sequence = match.group(0)

                if not started:
                    prefix.append(sequence)
                elif visible_index < end:
                    output.append(sequence)

                index = match.end()
                continue

            if start <= visible_index < end:
                if not started:
                    output.extend(prefix)
                    started = True

                output.append(line[index])

            visible_index += 1
            index += 1

            if started and visible_index >= end:
                break

        if output:
            output.append(ANSI_RESET)

        return "".join(output)

    def _content_width(self) -> int:
        # Leave one column unused to prevent terminal auto-wrap.
        return max(1, self.win.width - 1)

    def _max_top(self) -> int:
        return max(
            0,
            len(self.lines) - max(1, self.win.height),
        )

    def _max_left(self) -> int:
        return max(
            0,
            self.longest_line - self._content_width(),
        )

    def _draw(self) -> None:
        if not self.win.is_valid():
            return

        self.top = max(
            0,
            min(self.top, self._max_top()),
        )
        self.left = max(
            0,
            min(self.left, self._max_left()),
        )

        height = max(1, self.win.height)
        width = self._content_width()

        visible_lines = self.lines[self.top : self.top + height]

        rendered = [
            self._ansi_slice(
                line,
                self.left,
                width,
            )
            for line in visible_lines
        ]

        self.win.write(
            "\n".join(rendered),
            True,
        )

    def refresh(
        self,
        *,
        reset: bool = False,
    ) -> None:
        if not self.win.is_valid():
            return

        self.lines = self._capture().rstrip("\n").splitlines() or [""]

        self.longest_line = max(
            (self._visible_length(line) for line in self.lines),
            default=0,
        )

        if reset:
            self.top = 0
            self.left = 0

        self._draw()

    def render(self) -> None:
        self._draw()

    def hscroll(self, num: int) -> None:
        new_left = max(
            0,
            min(
                self.left + num,
                self._max_left(),
            ),
        )

        if new_left != self.left:
            self.left = new_left
            self._draw()

    def vscroll(self, num: int) -> None:
        new_top = max(
            0,
            min(
                self.top + num,
                self._max_top(),
            ),
        )

        if new_top != self.top:
            self.top = new_top
            self._draw()

    def click(
        self,
        x: int,
        y: int,
        button: int,
    ) -> None:
        del x, y, button
        _GDB_EXECUTE(
            f"focus {self.window_name}",
            False,
            True,
        )

    def _before_prompt(
        self,
        _event: None = None,
    ) -> None:
        self.refresh(reset=True)


def command_window(
    window_name: str,
    title: str,
    command: str,
    *,
    fallback_command: str | None = None,
    fallback_markers: tuple[str, ...] = (),
    fallback_title: str | None = None,
) -> Callable[
    [gdb.TuiWindow],
    PwndbgCommandWindow,
]:
    def factory(
        window: gdb.TuiWindow,
    ) -> PwndbgCommandWindow:
        return PwndbgCommandWindow(
            window,
            window_name,
            title,
            command,
            fallback_command=fallback_command,
            fallback_markers=fallback_markers,
            fallback_title=fallback_title,
        )

    return factory


gdb.register_window_type(
    "pwndbg_stackf_cmd",
    command_window(
        "pwndbg_stackf_cmd",
        "STACKF  rsp -> rbp",
        "stackf",
        fallback_command="stack 64",
        fallback_markers=FRAME_UNAVAILABLE_MARKERS,
        fallback_title="STACK  (frame unavailable)",
    ),
)

gdb.register_window_type(
    "pwndbg_retaddr_cmd",
    command_window(
        "pwndbg_retaddr_cmd",
        "RETADDR",
        "retaddr",
    ),
)


# ============================================================
# Pwndbg display settings
# ============================================================

_SETTINGS = (
    # Let native Pwndbg TUI sections use the full pane height.
    "set context-tui-adjust-height on",
    # Keep only the native sections used by this layout enabled.
    # Pwndbg will update these panes automatically.
    # "set context-sections regs disasm backtrace",
    # The command pane does not need space reserved for CLI context.
    "set context-reserve-lines never",
    # Keep enough backtrace entries available for scrolling.
    "set context-backtrace-lines 64",
    # Show backtrace offsets in hexadecimal.
    "set context-backtrace-hex on",
    # Fold repeated values in stack/telescope output.
    "set telescope-skip-repeating-val on",
    # Start folding after three repeated values.
    "set telescope-skip-repeating-val-min 3",
    # Include one pointer immediately after the current stack frame.
    "set telescope-frame-print-retaddr on",
    # Do not hide repeated entries referenced by registers.
    "set telescope-dont-skip-registers on",
    # Color the native backtrace pane.
    "set backtrace-prefix-color green,bold",
    "set backtrace-address-color yellow",
    "set backtrace-symbol-color cyan,bold",
)

for setting in _SETTINGS:
    try:
        _GDB_EXECUTE(
            setting,
            False,
            True,
        )
    except gdb.error as exc:
        gdb.write(
            f"[pwndbg_tui] {setting}: {exc}\n",
            gdb.STDERR,
        )


# ============================================================
# Layout
# ============================================================

_LAYOUT = " ".join(
    """
    tui new-layout pwndbg_pwn
    {-horizontal
        {
            {-horizontal
                pwndbg_disasm 3
                pwndbg_stackf_cmd 2
            } 7
            cmd 3
        } 4
        {
            pwndbg_regs 3
            pwndbg_backtrace 2
            pwndbg_retaddr_cmd 2
            pwndbg_legend 0
        } 1
    } 1
    status 0
    """.split()  # noqa: SIM905
)

try:
    _GDB_EXECUTE(
        "help layout pwndbg_pwn",
        False,
        True,
    )
except gdb.error:
    _GDB_EXECUTE(
        _LAYOUT,
        False,
        True,
    )
