import argparse
import os
import shlex
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import Event, Lock

import pwn
from watchdog.events import FileModifiedEvent, FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

ChangeSet = dict[Path, PurePosixPath]

REMOTE_EXITED = object()
REDEPLOY_REQUESTED = object()
USER_STOPPED = object()

USER_SITE_CACHE_TTL = 24 * 60 * 60


@dataclass(frozen=True)
class Args:
    """Deployment configuration and runtime arguments."""

    entrypoint: Path
    include_siblings: bool
    upload_only: bool
    remote_root: PurePosixPath
    ssh_connection: dict
    clear_screen: bool
    arguments: tuple[str, ...] = ()

    def watched_files(self) -> set[Path]:
        """Determines the set of local files to monitor based on the configuration."""
        if not self.include_siblings:
            return {self.entrypoint}
        directory = self.entrypoint.parent
        return {path.resolve() for path in directory.iterdir() if path.is_file()}


class ChangeWatcher:
    """Monitors file changes and manages pending deployment updates."""

    def __init__(self, args: Args) -> None:
        self.args = args
        self.pending = {
            path: local_to_remote(path, args.remote_root) for path in args.watched_files()
        }
        self.notified = Event()
        self.lock = Lock()
        self.mtime: dict[Path, int] = dict()

    def is_watched_file(self, path: Path) -> bool:
        """Determines if a given path is within the monitored scope."""
        if not path.is_file():
            return False
        if not self.args.include_siblings:
            return path == self.args.entrypoint
        return path.parent == self.args.entrypoint.parent

    def add(self, path: Path) -> None:
        """Adds a path to the pending change set if it has been modified."""
        with self.lock:
            if path in self.pending:
                return
            mtime = path.stat().st_mtime_ns
            if path in self.mtime and self.mtime[path] == mtime:
                return
            self.mtime[path] = mtime
            self.pending[path] = local_to_remote(path, self.args.remote_root)
            self.notified.set()

    def has_pending(self) -> bool:
        """Returns whether there are files waiting to be uploaded."""
        return bool(self.pending)

    def take_pending(self) -> ChangeSet:
        """Collects and clears all pending file changes."""
        if not self.has_pending():
            return {}
        with self.lock:
            pending = dict(self.pending)
            self.pending.clear()
            self.notified.clear()
            return pending

    def wait(self) -> None:
        """Blocks until a change is detected."""
        self.notified.wait()


@contextmanager
def watch_changes(args: Args):
    """Sets up a file system observer to notify the watcher of modifications."""
    watcher = ChangeWatcher(args)

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event: FileSystemEvent) -> None:
            if event.is_directory:
                return
            path = Path(event.src_path).resolve()
            if watcher.is_watched_file(path):
                watcher.add(path)

    entrydir = str(args.entrypoint.parent)
    observer = Observer()
    observer.schedule(Handler(), entrydir, event_filter=[FileModifiedEvent])
    observer.start()
    try:
        yield watcher
    finally:
        observer.stop()
        observer.join()


def tee[T: pwn.tube](process: T) -> T:
    """Mirrors a pwntools tube's I/O to the local system stdout."""
    import sys

    orig_send_raw = process.send_raw
    orig_recv_raw = process.recv_raw
    output = sys.__stdout__.buffer  # type: ignore sys.stdout is replaced by pwn.term

    def send_raw(data, *args, **kwargs):
        if data:
            output.write(data)
            output.flush()
        return orig_send_raw(data, *args, **kwargs)

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
        if data: # prevent spin block
            output.write(data)
            output.flush()
        return data

    process.send_raw = send_raw
    process.recv_raw = recv_raw
    return process


def parse_args() -> Args:
    parser = argparse.ArgumentParser(
        description="Upload a solve file to pwn.college, run it, and redeploy on changes."
    )
    parser.add_argument(
        "entrypoint",
        type=Path,
        help="main file to upload and execute",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="deploy and watch the main file's directory",
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=PurePosixPath,
        default="/tmp",
        help="remote deployment directory",
    )
    parser.add_argument(
        "--ssh",
        help="ssh connection string (e.g. user@host:port)",
        default="hacker@dojo.pwn.college",
    )
    parser.add_argument(
        "--upload-only",
        action="store_true",
        help="only upload files without executing",
    )
    parser.add_argument(
        "--no-clear-screen",
        action="store_true",
        help="disable clearing the terminal on each redeploy",
    )
    parser.add_argument(
        "args",
        nargs=argparse.REMAINDER,
        help="arguments to pass to the remote script",
    )
    namespace = parser.parse_args()
    entrypoint: Path = namespace.entrypoint.resolve()
    if not entrypoint.is_file():
        raise FileNotFoundError(entrypoint)

    ssh_str = namespace.ssh
    if "@" not in ssh_str:
        raise ValueError("Invalid SSH connection string, must be in format user@host[:port]")
    user_host, *port = ssh_str.split(":")
    user, host = user_host.split("@")
    ssh_connection = {
        "user": user,
        "host": host,
        **({"port": int(port[0])} if port else {}),
    }

    return Args(
        entrypoint,
        namespace.recursive,
        namespace.upload_only,
        namespace.directory,
        ssh_connection,
        not namespace.no_clear_screen,
        tuple(namespace.args),
    )


def local_to_remote(path: Path, remote_root: PurePosixPath) -> PurePosixPath:
    """Resolves the remote destination path for a given local file."""
    return remote_root / PurePosixPath(path.name)


def file_uploader(ssh: pwn.ssh, args: Args):

    if args.remote_root.as_posix() != "/tmp":
        ssh.system(f"mkdir -p {shlex.quote(str(args.remote_root))}").wait()

    # when file is 'touch'ed without modification, skip upload and only restart
    md5set: dict[Path, bytes] = dict()

    def upload_files(watcher: ChangeWatcher) -> None:
        """Uploads the specified set of files to the remote environment."""
        changes = watcher.take_pending()
        if not changes:
            return
        for local_path, remote_path in changes.items():
            md5 = pwn.hashlib.md5(local_path.read_bytes()).digest()
            if local_path in md5set and md5set[local_path] == md5:
                continue
            md5set[local_path] = md5
            ssh.upload(str(local_path.as_posix()), str(remote_path))

    return upload_files


def interrupt_remote(ssh: pwn.ssh, io: pwn.tubes.ssh.ssh_process) -> None:
    """Forcibly terminates the currently running remote process."""
    process_alive = io.sock is not None
    if process_alive and io.pid:
        # io.kill() won't kill the process, we have to do it manually
        ssh.system(f"kill -TERM {io.pid}").wait()


# The dojo's `python` is a nix binary wrapper that hard-codes
# `PYTHONNOUSERSITE=true`, so the conventional
# `~/.local/lib/pythonX.Y/site-packages` is dropped from sys.path even though
# the directory exists. `python -m site --user-site` still reports the path,
# and we re-introduce it through the `env` we hand to ssh.process so user
# packages (e.g. `dojotool`) remain importable.
def read_user_site_cache(cachefile: Path) -> bytes | None:
    """Reads a fresh user-site environment cache."""
    if not cachefile.exists():
        return None
    if time.time() - os.path.getmtime(cachefile) >= USER_SITE_CACHE_TTL:
        return None
    try:
        return cachefile.read_bytes()
    except OSError:
        return None


def discover_user_site(ssh: pwn.ssh) -> dict[str, str]:
    """Discover and cache the remote python's user-site directory."""
    cachefile = Path(ssh._get_cachefile(f"dojo-user-site-{ssh.host}-{ssh.port}"))
    env_output = read_user_site_cache(cachefile)
    if env_output is None:
        env_output = ssh.system("PYTHONPATH=$(python -m site --user-site) env -0").recvrepeat()
        cachefile.write_bytes(env_output)

    decoded = env_output.decode()
    return dict(line.split("=", 1) for line in decoded.split("\0") if line)


def remote_command(args: Args, ssh: pwn.ssh) -> tuple[list[str], dict[str, str]]:
    """Builds the remote (argv, env) for executing the entrypoint."""
    ep = args.entrypoint
    rf = str(local_to_remote(ep, args.remote_root))
    if ep.suffix == ".py":
        env = discover_user_site(ssh)
        return ["python3", rf, *args.arguments], env

    raise NotImplementedError(f"Unsupported file type: {ep.suffix or ep.name}")


def run_remote_until_change(
    ssh: pwn.ssh,
    args: Args,
    watcher: ChangeWatcher,
) -> object:
    """Executes the remote command and monitors for local file changes."""
    argv, env = remote_command(args, ssh)
    cwd = str(args.remote_root)
    io: pwn.tubes.ssh.ssh_process

    # env in ssh.system will replace the remote environment, use shell wrapper (ssh.system) for now.
    # see https://github.com/Gallopsled/pwntools/issues/2751
    with tee(ssh.process(argv, argv[0], cwd=cwd, env=env, aslr=True)) as io:  # type: ignore
        try:
            while True:
                io.recv(timeout=3)  # type: ignore
                if watcher.has_pending():
                    pwn.info("Local change detected, kill and redeploying...")
                    interrupt_remote(ssh, io)
                    return REDEPLOY_REQUESTED
        except EOFError:
            return REMOTE_EXITED
        except KeyboardInterrupt:
            interrupt_remote(ssh, io)
            return USER_STOPPED


def wait_for_redeploy(watcher: ChangeWatcher) -> object:
    """Wait for a local change when no remote process is active."""
    try:
        watcher.wait()
        pwn.info("Local change detected, redeploying...")
        return REDEPLOY_REQUESTED
    except KeyboardInterrupt:
        return USER_STOPPED


def can_clear_screen() -> bool:
    if not sys.stdout.isatty():
        return False
    if "PWNLIB_NOTERM" in os.environ:
        return False
    return True


def deploy_loop(args: Args, watcher: ChangeWatcher) -> None:
    """Orchestrates the continuous upload, execution, and redeploy cycle."""
    with pwn.ssh(**args.ssh_connection, raw=True) as ssh:
        upload_files = file_uploader(ssh, args)
        while True:
            upload_files(watcher)

            if args.upload_only:
                pwn.log.info_once("Upload-only mode enabled, skipping execution")
                result = REMOTE_EXITED
            else:
                result = run_remote_until_change(ssh, args, watcher)
                if result is USER_STOPPED:
                    return

            if result is REMOTE_EXITED:
                result = wait_for_redeploy(watcher)
            if result is USER_STOPPED:
                return
            assert result is REDEPLOY_REQUESTED

            # Clear the terminal on subsequent redeploys
            if args.clear_screen and can_clear_screen():
                sys.stdout.write("\x1b[2J\x1b[3J\x1b[H")
                sys.stdout.flush()


def main() -> None:
    args = parse_args()
    with watch_changes(args) as watcher:
        deploy_loop(args, watcher)


if __name__ == "__main__":
    main()
