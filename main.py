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


@dataclass(frozen=True)
class Repr:
    """Returns the literal string value in its repr for remote evaluation."""

    value: str

    def __repr__(self) -> str:
        return self.value


class ChangeWatcher:
    """Monitors file changes and manages pending deployment updates."""

    args: Args
    changed: set[Path]
    notified: Event
    lock: Lock
    mtime: dict[Path, int]

    def __init__(self, args: Args) -> None:
        self.args = args
        self.changed = set()
        self.notified = Event()
        self.lock = Lock()
        self.mtime = dict()

    def watched_files(self) -> set[Path]:
        """Gets the set of local files currently being monitored."""
        if not self.args.include_siblings:
            return {self.args.entrypoint}
        directory = self.args.entrypoint.parent
        return {path.resolve() for path in directory.iterdir() if path.is_file()}

    def is_watched_file(self, path: Path) -> bool:
        """Determines if a given path is within the monitored scope."""
        if not path.is_file():
            return False
        if not self.args.include_siblings:
            return path == self.args.entrypoint
        return path.parent == self.args.entrypoint.parent

    def change_set_for(self, paths: set[Path]) -> ChangeSet:
        """Maps local paths to their remote deployment targets."""
        return {path: local_to_remote(path, self.args.remote_root) for path in paths}

    def add(self, path: Path) -> None:
        """Adds a path to the pending change set if it has been modified."""
        with self.lock:
            if path in self.changed:
                return
            mtime = path.stat().st_mtime_ns
            if path in self.mtime and self.mtime[path] == mtime:
                return
            self.mtime[path] = mtime
            self.changed.add(path)
            self.notified.set()

    def drain(self) -> ChangeSet:
        """Collects and clears all pending file changes."""
        with self.lock:
            pending = set(self.changed)
            self.changed.clear()
            self.notified.clear()
        return self.change_set_for(pending)

    def wait(self) -> ChangeSet:
        """Blocks until a change is detected and returns the pending set."""
        self.notified.wait()
        return self.drain()


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
    namespace = parser.parse_args()
    entrypoint: Path = namespace.entrypoint.resolve()
    if not entrypoint.is_file():
        raise FileNotFoundError(entrypoint)
    return Args(entrypoint, namespace.recursive, namespace.directory)


def local_to_remote(path: Path, remote_root: PurePosixPath) -> PurePosixPath:
    """Resolves the remote destination path for a given local file."""
    return remote_root / PurePosixPath(path.name)


def upload_files(ssh: pwn.ssh, changes: ChangeSet, watcher: ChangeWatcher) -> None:
    """Uploads the specified set of files to the remote environment."""
    if not changes:
        return
    if watcher.args.remote_root.as_posix() != "/tmp":
        ssh.system(f"mkdir -p {shlex.quote(str(watcher.args.remote_root))}").wait()
    for local_path, remote_path in changes.items():
        ssh.upload(str(local_path.as_posix()), str(remote_path))
    changes.clear()


def interrupt_remote(ssh: pwn.ssh, io: pwn.tubes.ssh.ssh_process) -> None:
    """Forcibly terminates the currently running remote process."""
    process_alive = io.sock is not None
    if process_alive and io.pid:
        # io.kill() won't kill the process, we have to do it manually
        ssh.system(f"kill -9 {io.pid}").wait()


def on_dojo(argv: list[bytes]) -> None:
    """Detects and resolves the challenge executable path on the remote host."""
    from pathlib import Path
    import os
    import stat

    def find_challenge(search_path="/challenge"):
        xs = [
            bytes(f.absolute())
            for f in Path(search_path).iterdir()
            if f.is_file()
            and os.access(f, os.X_OK)
            and (f.stat().st_mode & stat.S_ISUID)
        ]
        if not xs:
            raise FileNotFoundError(f"No executable found in {search_path}")
        if len(xs) > 1:
            raise FileNotFoundError(f"Multiple executables found in {search_path}")
        return xs[0]

    for i, arg in enumerate(argv):
        if arg == b"DOJO_ARGS_CHALLENGE":
            argv[i] = find_challenge()


def remote_command(watcher: ChangeWatcher) -> list[str]:
    """Builds the shell command for executing the entrypoint on the remote."""

    ep = watcher.args.entrypoint
    if ep.suffix == ".py":
        return [
            "/run/dojo/bin/python3",
            str(local_to_remote(ep, watcher.args.remote_root)),
            "DOJO_ARGS_CHALLENGE",  # real argv[1] for ep will be injected by on_dojo at preexec stage.
        ]

    raise NotImplementedError(f"Unsupported file type: {ep.suffix or ep.name}")


def run_remote_until_change(
    ssh: pwn.ssh,
    watcher: ChangeWatcher,
    changeset: ChangeSet,
) -> object:
    """Executes the remote command and monitors for local file changes."""
    argv = remote_command(watcher)
    io: pwn.tubes.ssh.ssh_process

    with tee(
        ssh.process(
            argv,
            executable=argv[0],
            cwd=str(watcher.args.remote_root),
            aslr=True,
            preexec_fn=on_dojo,
            preexec_args=(Repr("argv"),),
        )
    ) as io:  # type: ignore
        try:
            while True:
                io.recv(timeout=3)  # type: ignore
                changeset.update(watcher.drain())
                if changeset:
                    pwn.info("Local change detected, kill and redeploying...")
                    interrupt_remote(ssh, io)
                    return REDEPLOY_REQUESTED
        except EOFError:
            return REMOTE_EXITED
        except KeyboardInterrupt:
            interrupt_remote(ssh, io)
            return USER_STOPPED


def wait_for_redeploy(watcher: ChangeWatcher, changeset: ChangeSet) -> object:
    """Wait for a local change when no remote process is active."""
    try:
        changeset.update(watcher.wait())
        pwn.info("Local change detected, redeploying...")
        return REDEPLOY_REQUESTED
    except KeyboardInterrupt:
        return USER_STOPPED


def deploy_loop(watcher: ChangeWatcher) -> None:
    """Orchestrates the continuous upload, execution, and redeploy cycle."""
    changeset = watcher.change_set_for(watcher.watched_files())
    with pwn.ssh(user="hacker", host="dojo.pwn.college", raw=True) as ssh:
        while True:
            upload_files(ssh, changeset, watcher)
            result = run_remote_until_change(ssh, watcher, changeset)
            if result is USER_STOPPED:
                return
            if result is REDEPLOY_REQUESTED:
                continue
            if wait_for_redeploy(watcher, changeset) is USER_STOPPED:
                return


def main() -> None:
    args = parse_args()
    with watch_changes(args) as watcher:
        deploy_loop(watcher)


if __name__ == "__main__":
    main()
