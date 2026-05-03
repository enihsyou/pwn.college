import argparse
import shlex
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import Event, Lock

import pwn
from watchdog.events import (
    FileModifiedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

ChangeSet = dict[Path, PurePosixPath]

PROJECT_ROOT = Path(__file__).resolve().parent
LOCAL_RUNNER = Path("dojo.py")

REMOTE_EXITED = object()
REDEPLOY_REQUESTED = object()
USER_STOPPED = object()


@dataclass(frozen=True)
class Args:
    entrypoint: Path
    include_siblings: bool
    remote_root: PurePosixPath


class ChangeWatcher:
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
        if not self.args.include_siblings:
            return {self.args.entrypoint}
        directory = self.args.entrypoint.parent
        return {path.resolve() for path in directory.iterdir() if path.is_file()}

    def is_watched_file(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if not self.args.include_siblings:
            return path == self.args.entrypoint
        return path.parent == self.args.entrypoint.parent

    def change_set_for(self, paths: set[Path]) -> ChangeSet:
        changes = {}
        for path in paths:
            relative_path = project_relative(path)
            changes[path] = local_to_remote(relative_path, self.args.remote_root)
        return changes

    def add(self, path: Path) -> None:
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
        with self.lock:
            pending = set(self.changed)
            self.changed.clear()
            self.notified.clear()
        return self.change_set_for(pending)

    def wait(self) -> ChangeSet:
        self.notified.wait()
        return self.drain()


@contextmanager
def watch_changes(args: Args):
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


def project_relative(path: Path) -> Path:
    resolved = path.resolve()
    try:
        return resolved.relative_to(PROJECT_ROOT)
    except ValueError as error:
        raise ValueError(
            f"{resolved} is outside project root {PROJECT_ROOT}"
        ) from error


def project_path(path: Path) -> Path:
    return PROJECT_ROOT / path


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
    entrypoint: Path = namespace.entrypoint
    assert project_relative(entrypoint)
    if not entrypoint.is_file():
        raise FileNotFoundError(entrypoint)
    return Args(entrypoint, namespace.recursive, namespace.directory)


def local_to_remote(path: Path, remote_root: PurePosixPath) -> PurePosixPath:
    return remote_root / PurePosixPath(path.name)


def validate_supported_file(path: Path) -> None:
    if path.suffix == ".py":
        return
    raise NotImplementedError(f"Unsupported file type: {path.suffix or path.name}")


def initial_change_set(watcher: ChangeWatcher) -> ChangeSet:
    changes = watcher.change_set_for(watcher.watched_files())
    changes[LOCAL_RUNNER] = local_to_remote(LOCAL_RUNNER, watcher.args.remote_root)
    return changes


def upload_files(ssh: pwn.ssh, changes: ChangeSet, watcher: ChangeWatcher) -> None:
    if not changes:
        return
    if LOCAL_RUNNER in changes and watcher.args.remote_root.as_posix() != "/tmp":
        ssh.system(f"mkdir -p {shlex.quote(str(watcher.args.remote_root))}").wait()
    for local_path, remote_path in changes.items():
        local_path = project_relative(
            local_path
        ).as_posix()  # to shirnk the path length in logs
        ssh.upload(str(local_path), str(remote_path))
    changes.clear()


def interrupt_remote(ssh: pwn.ssh, io: pwn.tubes.ssh.ssh_process) -> None:
    process_alive = io.sock is not None
    if process_alive and io.pid:
        # io.kill() won't kill the process, we have to do it manually
        ssh.system(f"kill -9 {io.pid}").wait()


def remote_command(watcher: ChangeWatcher) -> list[str]:
    return [
        "/run/dojo/bin/python3",
        str(local_to_remote(LOCAL_RUNNER, watcher.args.remote_root)),
        str(local_to_remote(watcher.args.entrypoint, watcher.args.remote_root)),
        "-d",
        str(watcher.args.remote_root),
    ]


def run_remote_until_change(
    ssh: pwn.ssh,
    watcher: ChangeWatcher,
    changeset: ChangeSet,
) -> object:
    argv = remote_command(watcher)
    io: pwn.tubes.ssh.ssh_process
    with tee(ssh.process(argv, executable=argv[0], aslr=True)) as io:  # type: ignore
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
    try:
        changeset.update(watcher.wait())
        pwn.info("Local change detected, redeploying...")
        return REDEPLOY_REQUESTED
    except KeyboardInterrupt:
        return USER_STOPPED


def deploy_loop(watcher: ChangeWatcher) -> None:
    changeset = initial_change_set(watcher)
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
    validate_supported_file(args.entrypoint)
    with watch_changes(args) as watcher:
        deploy_loop(watcher)


if __name__ == "__main__":
    main()
