# SPDX-License-Identifier: GPL-2.0-only
"""Observe an owned POSIX child without releasing its PID/process-group lease.

Some Apple Python builds omit os.waitid despite exporting its option constants.
The fallback is deliberately limited to the Darwin LP64 ABI, as declared by
sys/wait.h, sys/signal.h and sys/_types.h in the macOS SDK. It does not guess a
Linux siginfo layout, decode exit status or reap a child. The caller must own
all child reaping and retain the original leader until group cleanup finishes.
"""
import ctypes
import errno
import os
import platform
import signal
import sys


# A cleanup refusal must not trigger Popen.__del__ polling/reaping when an
# Evidence instance unwinds. Retain these finite failed owners until shutdown;
# never subsequently signal their numeric process groups from this quarantine.
_QUARANTINED_COMMANDS = []


def quarantine_failed_cleanup(process):
    _QUARANTINED_COMMANDS.append(process)


class _DarwinSigval(ctypes.Union):
    _fields_ = [("sival_int", ctypes.c_int), ("sival_ptr", ctypes.c_void_p)]


class _DarwinSiginfo(ctypes.Structure):
    _fields_ = [
        ("si_signo", ctypes.c_int), ("si_errno", ctypes.c_int),
        ("si_code", ctypes.c_int), ("si_pid", ctypes.c_int32),
        ("si_uid", ctypes.c_uint32), ("si_status", ctypes.c_int),
        ("si_addr", ctypes.c_void_p), ("si_value", _DarwinSigval),
        ("si_band", ctypes.c_long), ("reserved", ctypes.c_ulong * 7),
    ]


def _darwin_abi():
    # These are the SDK's LP64 layout and options, not a permissive allocation
    # of an oversized buffer with assumed prefix offsets. Reject other ABIs.
    offsets = tuple(getattr(_DarwinSiginfo, field).offset
                    for field, _ in _DarwinSiginfo._fields_)
    if (sys.platform != "darwin" or platform.machine() not in ("arm64", "x86_64")
            or ctypes.sizeof(ctypes.c_int) != 4
            or ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(_DarwinSiginfo) != 104
            or ctypes.alignment(_DarwinSiginfo) != 8
            or offsets != (0, 4, 8, 12, 16, 20, 24, 32, 40, 48)
            or tuple(getattr(os, name, None) for name in
                     ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")) != (1, 4, 1, 32)):
        raise RuntimeError("unsupported waitid ABI; require Python os.waitid or Darwin LP64")


class ChildWaiter:
    def __init__(self):
        self._python_waitid = getattr(os, "waitid", None)
        if callable(self._python_waitid):
            if not all(hasattr(os, name) for name in
                       ("P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
                raise RuntimeError("Python waitid lacks required WNOWAIT options")
            self.backend = "python-os.waitid"
        else:
            self._python_waitid = None
            _darwin_abi()
            # System install name, not a user-configurable library search path.
            self._libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            self._waitid = self._libc.waitid
            # idtype_t is an enum/int; id_t is uint32_t; siginfo_t is above.
            self._waitid.argtypes = [ctypes.c_int, ctypes.c_uint32,
                                    ctypes.POINTER(_DarwinSiginfo), ctypes.c_int]
            self._waitid.restype = ctypes.c_int
            self.backend = "darwin-libSystem.waitid-lp64"

    def exited_unreaped(self, pid):
        if not 0 < pid <= 0x7fffffff:
            raise ValueError("require a positive owned pid_t")
        options = os.WEXITED | os.WNOHANG | os.WNOWAIT
        if self._python_waitid is not None:
            result = self._python_waitid(os.P_PID, pid, options)
            if result is None:
                return False
            observed = result.si_pid
        else:
            info = _DarwinSiginfo()  # zero si_pid is required for WNOHANG.
            ctypes.set_errno(0)
            if self._waitid(os.P_PID, pid, ctypes.byref(info), options) != 0:
                error = ctypes.get_errno()
                if error == errno.EINTR:
                    return False  # caller checks cancellation/deadline again.
                if error == errno.ECHILD:
                    raise ChildProcessError(error, os.strerror(error))
                raise OSError(error, os.strerror(error))
            observed = info.si_pid
        if observed == 0:
            return False
        if observed != pid:
            # WNOWAIT did not reap, but a mismatched result cannot authorize
            # group cleanup. Treat the ownership observation as unusable.
            raise ChildProcessError("waitid returned a different child")
        return True

    def cleanup_owned_group(self, pid, receipt):
        """Signal only the retained child's group; independently prove EPERM.

        The caller created a new session with PGID == the original child PID
        and exclusively owns reaping. Every group action rechecks that lease.
        A successful signal is not a proof that descendants have exited; the
        process controls separately check release of their inherited lock.
        """
        exited = self.exited_unreaped(pid)  # ECHILD must precede any group action.
        receipt["leader_exited_before_cleanup"] = exited
        receipt["cleanup_pid"] = pid
        receipt["cleanup_pgid"] = pid
        receipt["group_cleanup"] = "attempting SIGKILL before original leader reap"
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            receipt["group_cleanup"] = "ESRCH before original leader reap"
        except PermissionError as error:
            receipt["group_signal_errno"] = error.errno
            if error.errno != errno.EPERM or sys.platform != "darwin":
                raise
            # Darwin killpg skips zombies and reports EPERM if it signaled no
            # member. EPERM alone cannot distinguish this from denied access.
            # Require an exited *owned* leader and an independently complete
            # group snapshot containing that retained leader and nothing else.
            if not self.exited_unreaped(pid):
                raise
            snapshot = self._darwin_group_snapshot(pid)
            receipt["darwin_group_snapshot"] = snapshot
            if (snapshot["bytes"] != ctypes.sizeof(ctypes.c_int32)
                    or snapshot["errno"] != 0 or snapshot["pids"] != [pid]):
                raise
            if not self.exited_unreaped(pid):
                raise ChildProcessError("lost exited leader during group proof")
            receipt["leader_exited_after_snapshot"] = True
            receipt["group_cleanup"] = "Darwin EPERM; sole retained exited leader proven"
        else:
            receipt["group_cleanup"] = "SIGKILL before original leader reap"

    def _darwin_group_snapshot(self, pid):
        # SDK libproc.h: int proc_listpids(uint32_t, uint32_t, void *, int).
        # PROC_PGRP_ONLY == 2 (sys/proc_info.h); pid_t is signed 32-bit.
        # XNU proc_info.c holds proc_list_lock across allproc AND zombproc.
        # A two-pid buffer is deliberately never resized: only exactly one
        # returned pid is accepted. Full buffers may be truncated. libproc
        # converts syscall errors to zero, which is never accepted as empty.
        if (sys.platform != "darwin" or platform.machine() not in ("arm64", "x86_64")
                or ctypes.sizeof(ctypes.c_void_p) != 8
                or ctypes.sizeof(ctypes.c_int) != 4):
            raise RuntimeError("unsupported Darwin proc_listpids ABI")
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        listpids = library.proc_listpids
        listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32,
                            ctypes.c_void_p, ctypes.c_int]
        listpids.restype = ctypes.c_int
        members = (ctypes.c_int32 * 2)()
        ctypes.set_errno(0)
        count = listpids(2, pid, members, ctypes.sizeof(members))
        error = ctypes.get_errno()
        valid = 0 < count <= ctypes.sizeof(members) and count % 4 == 0
        return {"backend": "darwin-libSystem.proc_listpids-pgrp",
                "bytes": count, "capacity_bytes": ctypes.sizeof(members),
                "errno": error, "pids": list(members)[:count // 4] if valid else []}
