import argparse
import shlex
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


@dataclass(frozen=True)
class Args:
    """Deployment configuration and runtime arguments."""

    entrypoint: Path
    include_siblings: bool
    remote_root: PurePosixPath
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
            path: local_to_remote(path, args.remote_root)
            for path in args.watched_files()
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
        output.write(data)
        output.flush()
        return orig_send_raw(data, *args, **kwargs)

    def recv_raw(numb, *args, **kwargs):
        data = orig_recv_raw(numb, *args, **kwargs) or b""  # orig may return str('')
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
        "args",
        nargs=argparse.REMAINDER,
        help="arguments to pass to the remote script",
    )
    namespace = parser.parse_args()
    entrypoint: Path = namespace.entrypoint.resolve()
    if not entrypoint.is_file():
        raise FileNotFoundError(entrypoint)
    return Args(
        entrypoint, namespace.recursive, namespace.directory, tuple(namespace.args)
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


def remote_command(args: Args) -> list[str]:
    """Builds the shell command for executing the entrypoint on the remote."""
    ep = args.entrypoint
    rf = str(local_to_remote(ep, args.remote_root))
    if ep.suffix == ".py":
        return ["/run/dojo/bin/python3", rf, *args.arguments]

    raise NotImplementedError(f"Unsupported file type: {ep.suffix or ep.name}")


def run_remote_until_change(
    ssh: pwn.ssh,
    args: Args,
    watcher: ChangeWatcher,
) -> object:
    """Executes the remote command and monitors for local file changes."""
    argv = remote_command(args)
    cwd = str(args.remote_root)
    io: pwn.tubes.ssh.ssh_process

    with tee(ssh.process(argv, argv[0], cwd=cwd, aslr=True)) as io:  # type: ignore
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


def deploy_loop(args: Args, watcher: ChangeWatcher) -> None:
    """Orchestrates the continuous upload, execution, and redeploy cycle."""
    with pwn.ssh(user="hacker", host="dojo.pwn.college", raw=True) as ssh:
        upload_files = file_uploader(ssh, args)
        while True:
            upload_files(watcher)
            result = run_remote_until_change(ssh, args, watcher)
            if result is USER_STOPPED:
                return
            if result is REDEPLOY_REQUESTED:
                continue
            if wait_for_redeploy(watcher) is USER_STOPPED:
                return


def main() -> None:
    args = parse_args()
    with watch_changes(args) as watcher:
        deploy_loop(args, watcher)


if __name__ == "__main__":
    main()
