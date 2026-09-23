Always use `uv run` to run scripts.

Solution `flag.py` files start with the module/challenge title and URL as comments. Import `pwn` and `find_challenge, submit` from `dojotool`, and call pwntools through `pwn.*`. Use `ctf()` as the entry point: locate the binary with `find_challenge()`, interact through `with pwn.process(...) as io`, keep challenge logic in small helpers such as `one_round(io)` when useful, and pass the captured flag or output to `submit(...)`. Call `ctf()` under an `if __name__ == "__main__":` guard.

Solution script commits: `feat: <module> - <challenge>` — copy the first line of the file.
