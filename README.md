# pwn.college

My attempts to the [pwn.college challenges](https://pwn.college/dojos), these write‑ups serves as a memo documenting my thought process for solving challenge problems, sometimes including a PoC.

The directory structure of the challenges keeps sync with [pwncollege/challenges](https://github.com/pwncollege/challenges). Some challenge directories are renamed from their original `level-*` names to the actual binary name for easier identification.

> [!IMPORTANT]
> Spoiler alert! Think before continue exploring. Avoid the temptation to copy-paste; try to solve these yourself first. Combined with AI, your own insights will yield much better results. Happy coding!
>
> You might be more interested in this writeup:
>
> - <https://writeups.kunull.net/pwn-college>
> - <https://github.com/Lo4pca/NoobCTF/blob/main/%E7%AC%94%E8%AE%B0/Pwn/pwn.college.md>
> - <https://lkliki.github.io/tags/PwnCollege/>
> - <https://www.cubeyond.net/volume/1/>

The [workspace](workspace) directory stores home‑directory configuration files intended to enhance the remote development workflow. For example, it includes scripts that allow retrieving the GUI desktop clipboard over SSH.

Disclaimer: All solutions approaches were independently developed by myself.

## Running solution scripts

Use `task init` after starting a challenge to initialize a local solution template
from the running challenge. The task-init script queries the pwn.college API for
the active dojo/module/challenge and then resolves the module and challenge names
from that dojo's API module list. It writes under
`challenges/{dojo}/{module_id}/{challenge_id}` using the exact API IDs and
preserves existing files.
Task loads `DOJO_ACCESS_TOKEN` from the ignored `.env` file; the same variable
can be exported when invoking `uv run python scripts/task-init.py` directly.

For the API contract, headers, request flow, and troubleshooting, see
[`docs/pwn_college_api.md`](docs/pwn_college_api.md).

If the solution needs additional files from the local `workspace/` tree, use
`task sync` to synchronize them to the challenge host.

Pass the solution script to `dojo.py` to upload and run it on the dojo:

```text
python dojo.py ./challenges/intro-to-cybersecurity/cryptography/cpa/solution.py
```

Use forward slashes in challenge paths, including on Windows.

---

Alternatively, if you wish to run a solution script directly on the dojo by
editing a file on the challenge host, make sure the
`dojotool` module synced over by `task sync` is importable by extending
`PYTHONPATH` accordingly:

```bash
PYTHONPATH=$(python -m site --user-site) python
```
