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
import sys


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
