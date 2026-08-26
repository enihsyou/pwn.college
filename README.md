# pwn.college

My attempts to the [pwn.college challenges](https://pwn.college/dojos), these write‑ups serves as a memo documenting my thought process for solving challenge problems, sometimes including a PoC.

The directory structure of the challenges keeps sync with [pwncollege/challenges](https://github.com/pwncollege/challenges). Some challenge directories are renamed from their original `level-*` names to the actual binary name for easier identification.

> [!IMPORTANT]
> Spoiler alert! Think before continue exploring. This repository documents my attempts and thought process rather than providing reference answers. You may get more out of it by trying to solve the challenges on your own first. Combined with AI, your own insights will yield much better results.
>
> You might be more interested in these writeups:
>
> - <https://writeups.kunull.net/pwn-college>
> - <https://github.com/Lo4pca/NoobCTF/blob/main/%E7%AC%94%E8%AE%B0/Pwn/pwn.college.md>
> - <https://lkliki.github.io/tags/PwnCollege/>
> - <https://www.cubeyond.net/volume/1/>

Disclaimer: All solutions approaches were independently developed by myself.

---

The [workspace](workspace) directory stores home‑directory configuration files intended to enhance the remote development workflow. For example, it includes scripts that allow retrieving the GUI desktop clipboard over SSH.

## Running solution scripts

After a challenge is started, `task init` initializes a local solution template
from the running challenge. The task-init script queries the pwn.college API
for the active dojo/module/challenge and then resolves the module and
challenge names from that dojo's API module list. It writes under
`challenges/{dojo}/{module_id}/{challenge_id}` using the exact API IDs and
preserves existing files.
`DOJO_ACCESS_TOKEN` is loaded from the ignored `.env` file; the same variable
can also be exported when invoking `uv run python scripts/task_init.py`
directly. `task submit` resolves the same active challenge and executes its
`flag.py` with `uv run`.

Notes on the API contract, headers, request flow, and troubleshooting are kept
in [`docs/pwn_college_api.md`](docs/pwn_college_api.md).

When a solution needs additional files from the local `workspace/` tree,
`task sync` synchronizes them to the challenge host.

A solution script is uploaded and run on the dojo with `dojo.py`:

```text
task submit
# or equivalently
python dojo.py ./challenges/intro-to-cybersecurity/cryptography/cpa/solution.py
```

Direct execution of a solution script on the dojo requires `PYTHONPATH` to be
extended so that the `dojotool` module synced over by `task sync` is importable:

```bash
PYTHONPATH=$(python -m site --user-site) python
```
