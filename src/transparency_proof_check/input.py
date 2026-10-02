"""Read one bounded POSIX regular file without following symlink components."""

import os
import stat

from .evidence import Limits, _limits, check_bytes, open_report


def check_file(path: str | os.PathLike[str], limits: Limits | None = None) -> dict:
    limits = _limits(limits)
    rejected = lambda code: open_report(code, limits=limits)
    flags = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK")
    if (os.name != "posix" or any(not hasattr(os, flag) for flag in flags)
            or os.open not in os.supports_dir_fd):
        return rejected("safe_local_read_unavailable")
    try:
        requested = os.fspath(path)
    except TypeError:
        return rejected("invalid_local_path")
    if type(requested) is not str or not requested or "\x00" in requested:
        return rejected("invalid_local_path")
    # Normalizing a symlink/../ path changes which file POSIX would resolve.
    if ".." in requested.split("/"):
        return rejected("parent_path_segment_not_supported")
    components = [p for p in os.path.abspath(requested).split("/") if p]
    if not components:
        return rejected("regular_file_required")
    directory = descriptor = None
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for component in components[:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(components[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return rejected("regular_file_required")
        if before.st_size > limits.input_bytes:
            return rejected("input_byte_budget_exceeded")
        chunks = []
        remaining = limits.input_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > limits.input_bytes:
            return rejected("input_byte_budget_exceeded")
        after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or len(raw) != after.st_size:
            return rejected("input_changed_during_read")
        return check_bytes(raw, limits)
    except OSError:
        return rejected("local_file_unavailable_or_symlink")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)
