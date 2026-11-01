"""Run an isolated local practice VM with native QEMU on Windows."""

import argparse
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import tempfile
import time
import uuid
from contextlib import ExitStack
from email.message import Message
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from scripts import pwn_college_api as api

ASSETS = Path(__file__).with_name("vm_assets")
DEFAULT_CACHE = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".cache")) / "pwn-college/vm"
GITHUB_PROXY = "https://gh-proxy.org/"
KERNEL_REF = "314c1135d3601fea2d313063bdc5fbf6fb1701cd"
KERNEL_SOURCE = re.compile(
    r"/software-exploitation-dojo/kernel-exploitation/files/([0-3])/(vmlinux|bzImage)$"
)
# Sources from challenges/legacy/common/Dockerfile.j2 at 0a4d91514c8077a5b77c25aff3ce2d6dc90c1181.
VMLINUX_URLS = {
    "0": "https://dl.dropboxusercontent.com/scl/fi/hkwgmkajzw2rzas068g66/vmlinux0?rlkey=q5kkd5br7ize6n1002ghpprz3&dl=1",
    "1": "https://dl.dropboxusercontent.com/scl/fi/uhhjp8yf65p81p31rql1e/vmlinux1?rlkey=jybroi9nsya54ffrevmnk89hg&dl=1",
    "2": "https://dl.dropboxusercontent.com/scl/fi/cfln31ihejxyco1xb4j2o/vmlinux2?rlkey=h2tt3yuo5xrw56hquam98y8gh&dl=1",
    "3": "https://dl.dropboxusercontent.com/scl/fi/zymtq9sit5qeko0l81ph2/vmlinux3?rlkey=eh89lpb19dhhuxfw7ifvckut1&dl=1",
}
MANIFEST_SCRIPT = """
import json, os
from pathlib import Path
root = Path('/challenge')
files = []
for folder, dirs, names in os.walk(root, followlinks=True):
    for name in names:
        path = Path(folder) / name
        if path.is_file() and (name in ('bzImage', 'vmlinux') or path.stat().st_size >= 3*1024*1024):
            files.append({'path': path.relative_to(root).as_posix(), 'source': str(path.resolve())})
print(json.dumps(files))
"""


def run(argv, **kwargs):
    return subprocess.run([str(arg) for arg in argv], check=True, **kwargs)


def output(argv):
    return run(argv, capture_output=True, text=True).stdout.strip()


def wsl(args, *argv, **kwargs):
    return run(["wsl.exe", "--distribution", args.wsl, "--exec", *argv], **kwargs)


def linux_path(args, path):
    return wsl(
        args, "wslpath", "-a", "-u", Path(path).resolve(), capture_output=True, text=True
    ).stdout.strip()


def rsync_path(path):
    return output(["cygpath", "-u", "-a", Path(path).resolve()])


def remote(args, command):
    ssh = output(["cygpath", "-w", args.rsync_ssh])
    return output([ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", args.host, command])


def rsync(args, source, destination, *options):
    run(
        [
            "rsync",
            "-avzP",
            "--copy-links",
            "--protect-args",
            "-e",
            f"{args.rsync_ssh} -o BatchMode=yes -o ConnectTimeout=15",
            *options,
            f"{args.host}:{source}",
            rsync_path(destination),
        ]
    )


def download_url(url):
    if urlparse(url).hostname in {"github.com", "raw.githubusercontent.com"}:
        return GITHUB_PROXY + url
    return url


def download_file(url, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".part")
    with urlopen(download_url(url), timeout=60) as response, temporary.open("wb") as stream:
        expected = response.headers.get("Content-Length")
        while block := response.read(1024 * 1024):
            stream.write(block)
        if expected is not None and stream.tell() != int(expected):
            raise ValueError(f"Incomplete download: {target.name}; partial file retained.")
    temporary.replace(target)
    return target


def download(url, directory):
    """Use the original attachment name as identity; do not hash cached files."""
    url = download_url(url)
    with urlopen(Request(url, method="HEAD"), timeout=30) as response:
        headers = Message()
        headers["Content-Disposition"] = response.headers.get("Content-Disposition", "")
        filename = headers.get_filename()
    if (
        not filename
        or filename == "unspecified"
        or filename in {".", ".."}
        or any(char in filename for char in "/\\:\x00")
    ):
        raise ValueError(f"HEAD did not provide a safe original filename: {url}")
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    if target.is_file():
        print(f"Reusing {target}")
        return target
    print(f"Downloading {filename}")
    return download_file(url, target)


def link_asset(target, link):
    if link.is_symlink():
        link.unlink()
    elif link.exists():
        raise ValueError(f"Refusing to replace a regular file with a symlink: {link}")
    try:
        link.symlink_to(target.resolve())
    except OSError as error:
        raise OSError(
            f"Cannot create {link}; enable Windows Developer Mode (start ms-settings:developers) "
            "or run with the symbolic-link privilege."
        ) from error


def cached_asset(args, item):
    source = item["source"]
    match = KERNEL_SOURCE.search(source)
    if match:
        version, name = match.groups()
        if name == "vmlinux":
            return download(VMLINUX_URLS[version], args.cache / "downloads")
        url = (
            f"https://raw.githubusercontent.com/pwncollege/software-exploitation-dojo/"
            f"{KERNEL_REF}/kernel-exploitation/files/{version}/bzImage"
        )
        # Raw responses need not carry Content-Disposition; the version scopes their fixed name.
        target = args.cache / "kernels" / version / "bzImage"
        if not target.is_file():
            download_file(url, target)
        return target
    if PurePosixPath(item["path"]).name in {"vmlinux", "bzImage"}:
        raise ValueError(
            f"Unknown official source for {item['path']}; provide --kernel/--vmlinux. "
            "Kernel files are never downloaded through rsync."
        )
    # A regular /challenge/bzImage has no shared identity across different challenges.
    origin = f"{args.host}:{source}"
    if source.startswith("/challenge/"):
        origin += f":{args.instance}"
    identity = hashlib.sha256(origin.encode()).hexdigest()[:20]
    target = args.cache / "remote" / identity / PurePosixPath(item["path"]).name
    if not target.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".part")
        rsync(args, "/challenge/" + item["path"], temporary)
        temporary.replace(target)
    return target


def resolve_kernel_sources(args, manifest):
    unresolved = [
        item
        for item in manifest
        if item["path"] in {"vmlinux", "bzImage"}
        and not KERNEL_SOURCE.search(item["source"])
        and not (args.vmlinux if item["path"] == "vmlinux" else args.kernel)
    ]
    if not unresolved:
        return
    dojo, module, challenge = args.instance.split("/")
    if (dojo, module) != ("software-exploitation", "kernel-exploitation"):
        raise ValueError(
            "Unknown kernel source; provide --kernel and --vmlinux for this challenge."
        )
    # The container can contain regular copies, losing the original symlink provenance.
    entry = json.loads(
        output(
            [
                "gh",
                "api",
                (
                    f"repos/pwncollege/software-exploitation-dojo/contents/"
                    f"{module}/{challenge}/vmlinux?ref={KERNEL_REF}"
                ),
            ]
        )
    )
    target = entry.get("target", "")
    match = re.fullmatch(r"\.\./files/([0-3])/vmlinux", target)
    if not match:
        raise ValueError(
            f"Cannot resolve official kernel version from {target!r}; provide --kernel/--vmlinux."
        )
    version = match[1]
    print(f"Official kernel: {challenge} -> files/{version}")
    for item in unresolved:
        item["source"] = f"/software-exploitation-dojo/{module}/files/{version}/{item['path']}"


def pull_challenge(args, directory):
    manifest = json.loads(remote(args, shlex.join(["python3", "-c", MANIFEST_SCRIPT])))
    for item in manifest:
        path = PurePosixPath(item["path"])
        if (
            path.is_absolute()
            or ".." in path.parts
            or any(char in str(path) for char in "\\:\r\n\t\x00")
        ):
            raise ValueError(f"Unsafe remote challenge path: {path}")
    resolve_kernel_sources(args, manifest)
    excluded = [f"--exclude=/{item['path']}" for item in manifest]
    for marker in (".kaslr", ".panic_on_oops", ".nopti", ".initvm"):
        (directory / marker).unlink(missing_ok=True)
    rsync(args, "/challenge/", directory, *excluded)
    for item in manifest:
        link = directory / item["path"]
        link.parent.mkdir(parents=True, exist_ok=True)
        override = (
            args.kernel
            if item["path"] == "bzImage"
            else (args.vmlinux if item["path"] == "vmlinux" else None)
        )
        link_asset(override or cached_asset(args, item), link)
    for name, override in (("bzImage", args.kernel), ("vmlinux", args.vmlinux)):
        if override and not (directory / name).is_symlink():
            link_asset(override, directory / name)
    if not (directory / "bzImage").is_file():
        raise ValueError("No bzImage in /challenge; supply --kernel for this challenge.")


def boot_flags(challenge, args):
    kaslr = (challenge / ".kaslr").exists() if args.kaslr is None else args.kaslr
    panic = (
        (challenge / ".panic_on_oops").exists()
        if args.panic_on_oops is None
        else args.panic_on_oops
    )
    pti = not (challenge / ".nopti").exists() if args.pti is None else args.pti
    flags = [] if kaslr else ["nokaslr"]
    if panic:
        flags.extend(["oops=panic", "panic_on_warn=1"])
    if not pti:
        flags.append("nopti")
    return flags


def read_state(path):
    if not path.is_file():
        raise ValueError(
            f"No saved state at {path}; run prepare then start, or choose --instance dojo/module/challenge."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def qmp(state, command):
    with (
        socket.create_connection(("127.0.0.1", state["qmp_port"]), timeout=3) as connection,
        connection.makefile("rwb") as stream,
    ):

        def receive():
            while line := stream.readline():
                message = json.loads(line)
                if "error" in message:
                    raise ValueError(f"QMP: {message['error']}")
                if "event" not in message:
                    return message
            raise ValueError("QMP connection closed before replying")

        def execute(name):
            stream.write(json.dumps({"execute": name}).encode() + b"\n")
            stream.flush()
            return receive()["return"]

        receive()
        execute("qmp_capabilities")
        if execute("query-uuid")["UUID"] != state["uuid"]:
            raise ValueError("QMP UUID mismatch; refusing to control another VM.")
        return execute(command)


def running(state):
    try:
        qmp(state, "query-status")
        return True
    except ConnectionRefusedError:
        return False


def stop(state):
    if not running(state):
        print("VM is already stopped.")
        return
    try:
        qmp(state, "quit")
    except ConnectionResetError:
        pass
    for _ in range(50):
        try:
            if not running(state):
                print("VM stopped; files and logs retained.")
                return
        except ConnectionResetError:
            pass
        time.sleep(0.1)
    raise ValueError("VM did not stop; refusing to kill a process by PID.")


def ssh_options(state):
    return [
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={state['known_hosts']}",
        "-o",
        "ControlPath=none",
        "-i",
        state["key"],
    ]


def ssh_command(state, *command):
    return [
        "ssh",
        *ssh_options(state),
        "-p",
        str(state["ssh_port"]),
        *(["-t"] if not command else []),
        "hacker@127.0.0.1",
        *command,
    ]


def scp_command(state, source, destination, recursive):
    return [
        "scp",
        *ssh_options(state),
        "-P",
        str(state["ssh_port"]),
        *(["-r"] if recursive else []),
        str(source),
        f"hacker@127.0.0.1:{destination}",
    ]


def wait_for_ssh(state, timeout):
    print(f"Waiting up to {timeout}s for SSH on 127.0.0.1:{state['ssh_port']}", flush=True)
    print(f"Boot log: {state['log']}", flush=True)
    deadline = time.monotonic() + timeout
    with Path(state["log"]).open("rb") as log:
        log.seek(state["boot_log_offset"])
        tail = b""
        while time.monotonic() < deadline:
            if not running(state):
                raise ValueError(f"QEMU exited; see {state['log']}")
            tail = (tail + log.read())[-4096:]
            if b"Kernel panic - not syncing" in tail:
                raise ValueError(
                    f"Guest kernel panic; VM retained for inspection. See {state['log']}"
                )
            try:
                with socket.create_connection(
                    ("127.0.0.1", state["ssh_port"]), timeout=1
                ) as connection:
                    if connection.recv(255).startswith(b"SSH-"):
                        print(
                            f"SSH ready on 127.0.0.1:{state['ssh_port']}; instance {state['instance']}"
                        )
                        return
            except (ConnectionError, TimeoutError):
                pass
            time.sleep(0.5)
    raise ValueError(f"SSH not ready after {timeout}s; VM retained. See {state['log']}")


def build_filesystem(args, state):
    key = Path(state["key"])
    if not key.is_file():
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key])
    (args.cache / "rootfs").mkdir(parents=True, exist_ok=True)
    directory = Path(state["directory"])
    keys = [key.with_name(key.name + ".pub").read_text(encoding="utf-8").strip()]
    user_key = Path.home() / ".ssh/id_ed25519.pub"
    if user_key.is_file():
        keys.append(user_key.read_text(encoding="utf-8").strip())
    (directory / "authorized_keys").write_text(
        "\n".join(keys) + "\n", encoding="utf-8", newline="\n"
    )
    (directory / "challenge-path").write_text(
        linux_path(args, state["challenge"]) + "\n", encoding="utf-8", newline="\n"
    )
    paths = [args.cache / "rootfs", directory, ASSETS / "init"]
    wsl(
        args,
        "bash",
        linux_path(args, ASSETS / "build.sh"),
        *(linux_path(args, path) for path in paths),
    )


def launch(args, state):
    directory = Path(state["directory"])
    challenge = Path(state["challenge"])
    with ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(3)]
        for connection in sockets:
            connection.bind(("127.0.0.1", 0))
        state.update(
            zip(
                ("ssh_port", "gdb_port", "qmp_port"),
                (connection.getsockname()[1] for connection in sockets),
            )
        )
    public_key = (directory / "host_key.pub").read_text().strip()
    Path(state["known_hosts"]).write_text(
        f"[127.0.0.1]:{state['ssh_port']} {public_key}\n", encoding="utf-8", newline="\n"
    )
    flags = boot_flags(challenge, args)
    state["boot_flags"] = flags
    state["settings"] = {
        "kaslr": "nokaslr" not in flags,
        "panic_on_oops": "oops=panic" in flags,
        "pti": "nopti" not in flags,
    }
    state["uuid"] = str(uuid.uuid4())
    Path(state["addresses"]).write_text("", encoding="utf-8")
    argv = [
        args.qemu,
        "-accel",
        "tcg",
        "-cpu",
        "qemu64,+smep,+smap",
        "-m",
        "2G",
        "-smp",
        "1",
        "-kernel",
        str(challenge / "bzImage"),
        "-initrd",
        str(directory / "initramfs.cpio.gz"),
        "-append",
        " ".join(["console=ttyS0", "rdinit=/init", *flags]),
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-serial",
        f"file:{state['addresses']}",
        "-no-reboot",
        "-uuid",
        state["uuid"],
        "-qmp",
        f"tcp:127.0.0.1:{state['qmp_port']},server=on,wait=off",
        "-gdb",
        f"tcp:127.0.0.1:{state['gdb_port']}",
        "-device",
        "e1000,netdev=net0",
        "-netdev",
        f"user,id=net0,hostfwd=tcp:127.0.0.1:{state['ssh_port']}-:22",
    ]
    with Path(state["log"]).open("ab") as log:
        log.write(f"\n--- {time.ctime()} {state['uuid']} ---\n".encode())
        log.flush()
        state["boot_log_offset"] = log.tell()
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    state["pid"] = process.pid
    write_json(directory / "state.json", state)
    write_json(args.cache / "last.json", {"instance": state["instance"]})
    for _ in range(100):
        if process.poll() is not None:
            raise ValueError(f"QEMU exited with {process.returncode}; see {state['log']}")
        if running(state):
            break
        time.sleep(0.1)
    else:
        raise ValueError("QMP not ready; instance state retained for stop/logs.")
    print(f"Boot flags: {' '.join(flags) or '(kernel defaults)'}")
    wait_for_ssh(state, args.timeout)


def prepare(args):
    metadata = api.current_challenge_metadata()
    instance = f"{metadata.dojo_id}/{metadata.module_id}/{metadata.challenge_id}"
    if args.instance and args.instance != instance:
        raise ValueError(
            "--instance differs from the API's current challenge; refusing to sync another topic."
        )
    args.instance = instance
    directory = instance_directory(args.cache, instance)
    state_path = directory / "state.json"
    if state_path.exists():
        state = read_state(state_path)
        if running(state):
            raise ValueError(f"VM is still running: {instance}; stop that instance before prepare.")
    directory.mkdir(parents=True, exist_ok=True)
    challenge = (
        Path(tempfile.gettempdir())
        / "pwn-college-vm"
        / directory.relative_to(args.cache / "instances")
    )
    challenge.mkdir(parents=True, exist_ok=True)
    print(f"Challenge: {instance}\nWorkspace: {challenge}")
    pull_challenge(args, challenge)
    state = {
        "instance": instance,
        "directory": str(directory),
        "challenge": str(challenge),
        "key": str(directory / "id_ed25519"),
        "known_hosts": str(directory / "known_hosts"),
        "log": str(directory / "vm.log"),
        "addresses": str(directory / "addresses.log"),
        "wsl": args.wsl,
    }
    print("Building initramfs...", flush=True)
    build_filesystem(args, state)
    write_json(directory / "prepared.json", state)
    write_json(args.cache / "last.json", {"instance": instance})
    command = subprocess.list2cmdline(
        [
            "uv",
            "run",
            "python",
            "-m",
            "scripts.vm",
            "--cache",
            str(args.cache),
            "--instance",
            instance,
            "start",
        ]
    )
    print(f"Prepared: {directory / 'initramfs.cpio.gz'}\nRun: {command}")


def start(args):
    instance = args.instance or read_state(args.cache / "last.json")["instance"]
    directory = instance_directory(args.cache, instance)
    state_path = directory / "state.json"
    state = read_state(state_path) if state_path.exists() else None
    if state is not None and running(state):
        print(f"Already running: {instance}; use restart to change boot options.")
    else:
        state = read_state(directory / "prepared.json")
        state["qemu"] = args.qemu
        launch(args, state)
    print(f"SSH: ssh 127.0.0.1 -l hacker -p {state['ssh_port']}")


def instance_directory(cache, instance):
    parts = instance.split("/")
    if len(parts) != 3 or any(
        part in {".", ".."} or not re.fullmatch(r"[\w.~-]+", part) for part in parts
    ):
        raise ValueError("Instance must be three safe IDs: dojo/module/challenge")
    return cache.joinpath("instances", *parts)


def debug(args, state):
    symbols = Path(state["challenge"]) / "vmlinux"
    if not symbols.is_file():
        raise ValueError("No vmlinux; start with --vmlinux pointing to matching kernel symbols.")
    addresses = Path(state["addresses"]).read_text().splitlines()
    kernel = next((line.split()[1] for line in addresses if line.startswith("kernel ")), None)
    if kernel is None or "ready" not in addresses:
        raise ValueError("Guest symbol addresses are not ready; inspect logs first.")
    vmlinux = linux_path(args, symbols.resolve())
    nm = wsl(args, "nm", "--defined-only", vmlinux, capture_output=True, text=True).stdout
    linked_text = next(
        (line.split()[0] for line in nm.splitlines() if line.split()[-1] == "_text"), None
    )
    if linked_text is None:
        raise ValueError("vmlinux has no _text symbol; supply matching unstripped kernel symbols.")
    offset = int(kernel, 16) - int(linked_text, 16)
    commands = [
        f"exec-file {json.dumps(vmlinux)}",
        f"symbol-file {json.dumps(vmlinux)} -o {offset:#x}",
        f"target remote 127.0.0.1:{state['gdb_port']}",
    ]
    sections = {}
    for line in addresses:
        if line.startswith("module\t"):
            _, file, section, address = line.split("\t")
            if section not in {".symtab", ".strtab"}:
                sections.setdefault(file, {})[section] = address
    for file, locations in sections.items():
        module = linux_path(args, Path(state["challenge"]) / file)
        text = locations.pop(".text")
        extra = " ".join(
            f"-s {shlex.quote(section)} {address}" for section, address in locations.items()
        )
        commands.append(f"add-symbol-file {json.dumps(module)} {text} {extra}")
    argv = ["gdb", "-q", "-ex", "set confirm off"]
    for command in commands:
        argv.extend(["-ex", command])
    wsl(args, *argv)


def logs(state, follow):
    with Path(state["log"]).open(encoding="utf-8", errors="replace") as stream:
        while True:
            block = stream.read(8192)
            if block:
                print(block, end="", flush=True)
            elif follow:
                time.sleep(0.2)
            else:
                return


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--instance", help="saved dojo/module/challenge; defaults to last used VM")
    commands = parser.add_subparsers(dest="command", required=True)
    preparation = commands.add_parser(
        "prepare", help="download challenge files and build initramfs"
    )
    preparation.add_argument("--wsl", default="Ubuntu")
    preparation.add_argument("--host", default="hacker@dojo.pwn.college")
    preparation.add_argument("--rsync-ssh", default="/usr/bin/ssh")
    preparation.add_argument("--kernel", type=Path, help="explicit bzImage for another challenge")
    preparation.add_argument("--vmlinux", type=Path, help="explicit matching symbols")
    for name in ("start", "restart"):
        sub = commands.add_parser(name)
        sub.add_argument("--kaslr", action=argparse.BooleanOptionalAction, default=None)
        sub.add_argument("--panic-on-oops", action=argparse.BooleanOptionalAction, default=None)
        sub.add_argument("--pti", action=argparse.BooleanOptionalAction, default=None)
        sub.add_argument("--qemu", default="qemu-system-x86_64" if name == "start" else None)
        sub.add_argument("--timeout", type=int, default=180, help="SSH boot timeout in seconds")
    commands.add_parser("stop")
    commands.add_parser("connect")
    commands.add_parser("debug")
    copy = commands.add_parser("cp", help="copy a local file or directory into the VM")
    copy.add_argument("-r", "--recursive", action="store_true")
    copy.add_argument("source", type=Path)
    copy.add_argument("destination", nargs="?", default="/home/hacker/")
    log_parser = commands.add_parser("logs")
    log_parser.add_argument("--follow", "-f", action="store_true")
    execute = commands.add_parser("exec")
    execute.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.cache = args.cache.resolve()
    if args.command == "cp":
        args.source = args.source.resolve()
        if not args.source.exists():
            parser.error(f"source does not exist: {args.source}")
        if args.source.is_dir() and not args.recursive:
            parser.error("copying a directory requires -r")
    if args.command == "exec":
        if args.argv and args.argv[0] == "--":
            args.argv = args.argv[1:]
        if not args.argv:
            parser.error("exec requires a command")
    for name in ("kernel", "vmlinux"):
        if value := getattr(args, name, None):
            if not value.is_file():
                parser.error(f"{name} does not exist: {value}")
            setattr(args, name, value.resolve())
    return args


def main():
    args = parse_args()
    if os.name != "nt":
        raise SystemExit("This launcher targets native Windows QEMU; see docs/vm.md.")
    try:
        if args.command == "prepare":
            prepare(args)
            return 0
        if args.command == "start":
            start(args)
            return 0
        instance = args.instance or read_state(args.cache / "last.json")["instance"]
        state = read_state(instance_directory(args.cache, instance) / "state.json")
        if args.command == "stop":
            stop(state)
        elif args.command == "logs":
            logs(state, args.follow)
        elif args.command == "restart":
            stop(state)
            args.qemu = args.qemu or state["qemu"]
            for setting, value in state["settings"].items():
                if getattr(args, setting) is None:
                    setattr(args, setting, value)
            start(args)
        elif not running(state):
            raise ValueError("VM is stopped; use start to boot the prepared challenge offline.")
        elif args.command == "connect":
            run(ssh_command(state))
        elif args.command == "exec":
            run(ssh_command(state, shlex.join(args.argv)))
        elif args.command == "cp":
            run(scp_command(state, args.source, args.destination, args.recursive))
        elif args.command == "debug":
            args.wsl = state["wsl"]
            debug(args, state)
    except KeyboardInterrupt:
        return 130
    except (api.ApiError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Error: {error}")
        return error.returncode if isinstance(error, subprocess.CalledProcessError) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
