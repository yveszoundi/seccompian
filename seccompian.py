#!/usr/bin/env python3

import logging
import os
import sys
import argparse
import copy
import subprocess
import json

log = logging.getLogger()
log.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)

APP_VERSION = "0.0.1"

DEFAULT_TEST_TIMEOUT = 120

# Need a reasonable baseline to start with
# See https://gist.github.com/invidian/34b6222a030718b4b4d77cde25725dcf
SYSCALL_NAMES_MINIMAL = {
  "arch_prctl",
  "clone",
  "close",
  "execve",
  "exit",
  "exit_group",
  "fcntl",
  "gettid",
  "mmap",
  "openat",
  "read",
  "rt_sigaction",
  "rt_sigprocmask",
  "sched_getaffinity",
  "sigaltstack",
  "write",
  "fstatfs",
  "getdents64",
  "capget",
  "capset",
  "prctl",
  "fstat",
  "newfstatat",
  "setgroups",
  "setgid",
  "setuid",
  "chdir",
  "getppid"
}

# See mainly this: https://filippo.io/linux-syscall-table/
SYSCALL_NAMES_ALL = [
  "_sysctl",
  "accept",
  "accept4",
  "access",
  "acct",
  "add_key",
  "adjtimex",
  "afs_syscall",
  "alarm",
  "arch_prctl",
  "bind",
  "brk",
  "capget",
  "capset",
  "chdir",
  "chmod",
  "chown",
  "chroot",
  "clock_adjtime",
  "clock_getres",
  "clock_gettime",
  "clock_nanosleep",
  "clock_settime",
  "clone",
  "close",
  "connect",
  "creat",
  "create_module",
  "delete_module",
  "dup",
  "dup2",
  "dup3",
  "epoll_create",
  "epoll_create1",
  "epoll_ctl",
  "epoll_ctl_old",
  "epoll_pwait",
  "epoll_wait",
  "epoll_wait_old",
  "eventfd",
  "eventfd2",
  "execve",
  "exit",
  "exit_group",
  "faccessat",
  "fadvise64",
  "fallocate",
  "fanotify_init",
  "fanotify_mark",
  "fchdir",
  "fchmod",
  "fchmodat",
  "fchown",
  "fchownat",
  "fcntl",
  "fdatasync",
  "fgetxattr",
  "finit_module",
  "flistxattr",
  "flock",
  "fork",
  "fremovexattr",
  "fsetxattr",
  "fstat",
  "fstatfs",
  "fsync",
  "ftruncate",
  "futex",
  "futimesat",
  "get_kernel_syms",
  "get_mempolicy",
  "get_robust_list",
  "get_thread_area",
  "getcpu",
  "getcwd",
  "getdents",
  "getdents64",
  "getegid",
  "geteuid",
  "getgid",
  "getgroups",
  "getitimer",
  "getpeername",
  "getpgid",
  "getpgrp",
  "getpid",
  "getpmsg",
  "getppid",
  "getpriority",
  "getresgid",
  "getresuid",
  "getrlimit",
  "getrusage",
  "getsid",
  "getsockname",
  "getsockopt",
  "gettid",
  "gettimeofday",
  "getuid",
  "getxattr",
  "init_module",
  "inotify_add_watch",
  "inotify_init",
  "inotify_init1",
  "inotify_rm_watch",
  "io_cancel",
  "io_destroy",
  "io_getevents",
  "io_setup",
  "io_submit",
  "ioctl",
  "ioperm",
  "iopl",
  "ioprio_get",
  "ioprio_set",
  "kcmp",
  "kexec_load",
  "keyctl",
  "kill",
  "lchown",
  "lgetxattr",
  "link",
  "linkat",
  "listen",
  "listxattr",
  "llistxattr",
  "lookup_dcookie",
  "lremovexattr",
  "lseek",
  "lsetxattr",
  "lstat",
  "madvise",
  "mbind",
  "migrate_pages",
  "mincore",
  "mkdir",
  "mkdirat",
  "mknod",
  "mknodat",
  "mlock",
  "mlockall",
  "mmap",
  "modify_ldt",
  "mount",
  "move_pages",
  "mprotect",
  "mq_getsetattr",
  "mq_notify",
  "mq_open",
  "mq_timedreceive",
  "mq_timedsend",
  "mq_unlink",
  "mremap",
  "msgctl",
  "msgget",
  "msgrcv",
  "msgsnd",
  "msync",
  "munlock",
  "munlockall",
  "munmap",
  "name_to_handle_at",
  "nanosleep",
  "newfstatat",
  "nfsservctl",
  "open",
  "open_by_handle_at",
  "openat",
  "pause",
  "perf_event_open",
  "personality",
  "pipe",
  "pipe2",
  "pivot_root",
  "poll",
  "ppoll",
  "prctl",
  "pread64",
  "preadv",
  "prlimit64",
  "process_vm_readv",
  "process_vm_writev",
  "pselect6",
  "ptrace",
  "putpmsg",
  "pwrite64",
  "pwritev",
  "query_module",
  "quotactl",
  "read",
  "readahead",
  "readlink",
  "readlinkat",
  "readv",
  "reboot",
  "recvfrom",
  "recvmmsg",
  "recvmsg",
  "remap_file_pages",
  "removexattr",
  "rename",
  "renameat",
  "request_key",
  "restart_syscall",
  "rmdir",
  "rt_sigaction",
  "rt_sigpending",
  "rt_sigprocmask",
  "rt_sigqueueinfo",
  "rt_sigreturn",
  "rt_sigsuspend",
  "rt_sigtimedwait",
  "rt_tgsigqueueinfo",
  "sched_get_priority_max",
  "sched_get_priority_min",
  "sched_getaffinity",
  "sched_getparam",
  "sched_getscheduler",
  "sched_rr_get_interval",
  "sched_setaffinity",
  "sched_setparam",
  "sched_setscheduler",
  "sched_yield",
  "security",
  "select",
  "semctl",
  "semget",
  "semop",
  "semtimedop",
  "sendfile",
  "sendmmsg",
  "sendmsg",
  "sendto",
  "set_mempolicy",
  "set_robust_list",
  "set_thread_area",
  "set_tid_address",
  "setdomainname",
  "setfsgid",
  "setfsuid",
  "setgid",
  "setgroups",
  "sethostname",
  "setitimer",
  "setns",
  "setpgid",
  "setpriority",
  "setregid",
  "setresgid",
  "setresuid",
  "setreuid",
  "setrlimit",
  "setsid",
  "setsockopt",
  "settimeofday",
  "setuid",
  "setxattr",
  "shmat",
  "shmctl",
  "shmdt",
  "shmget",
  "shutdown",
  "sigaltstack",
  "signalfd",
  "signalfd4",
  "socket",
  "socketpair",
  "splice",
  "stat",
  "statfs",
  "swapoff",
  "swapon",
  "symlink",
  "symlinkat",
  "sync",
  "sync_file_range",
  "syncfs",
  "sysfs",
  "sysinfo",
  "syslog",
  "tee",
  "tgkill",
  "time",
  "timer_create",
  "timer_delete",
  "timer_getoverrun",
  "timer_gettime",
  "timer_settime",
  "timerfd_create",
  "timerfd_gettime",
  "timerfd_settime",
  "times",
  "tkill",
  "truncate",
  "tuxcall",
  "umask",
  "umount2",
  "uname",
  "unlink",
  "unlinkat",
  "unshare",
  "uselib",
  "ustat",
  "utime",
  "utimensat",
  "utimes",
  "vfork",
  "vhangup",
  "vmsplice",
  "vserver",
  "wait4",
  "waitid",
  "write",
  "writev"
]

class Syscalls:
  def __init__(self, keep_table, baseline):
    self.names = []
    self.action = "SCMP_ACT_ALLOW"

    for idx, keep_syscall in enumerate(keep_table):
      if keep_syscall:
        self.names.append(baseline[idx])

class SeccompProfile:
  def __init__(self, keep_table, baseline):
    self.defaultAction = "SCMP_ACT_ERRNO"
    self.syscalls = [Syscalls(keep_table, baseline)]

  def toJSON(self):
    return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

def save_seccomp_as_json(seccomp_profile, dest_file):
  with open(dest_file, 'w') as f:
    f.write(seccomp_profile.toJSON())

class Test:
  def __init__(self, command_and_arguments, timeout):
    self.command_and_arguments = command_and_arguments
    self.timeout = timeout

def run_test_successfully(cmd):
  cmdline = cmd.command_and_arguments
  log.info("Running command: %s" % cmdline)

  try:
    p = subprocess.run(cmdline, timeout=cmd.timeout)
    return p.returncode == 0
  except subprocess.TimeoutExpired:
    print("Test took too long to complete")
    return False

def parse_test_files(tests_folder, timeout):
  tests = []

  for file in os.listdir(tests_folder):
    if file.endswith(".test"):
      test = parse_test_file(os.path.join(tests_folder, file), timeout)
      tests.append(test)

  return tests

def parse_test_file(test_file, timeout):
  test_args = []

  with open(test_file, 'r') as f:
    for line in f.readlines():
      line_stripped = line.strip()

      if len(line_stripped) != 0:
        test_args.append(line_stripped)

  if len(test_args) == 0:
    raiseRuntimeError("No command or arguments found in test file '{test_file}".format(test_file = test_file))

  return Test(test_args, timeout)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--tests-folder", type=str, required=True)
  parser.add_argument("--tests-timeout-secs", type=int, default=DEFAULT_TEST_TIMEOUT, required=False)
  parser.add_argument("--seccomp-file-dest", type=str, required=True)
  parser.add_argument("--version", action="version", version="%(prog)s " + APP_VERSION)

  args = parser.parse_args()
  seccomp_file_dest = args.seccomp_file_dest
  tests_folder = args.tests_folder
  cmd_timeout = args.tests_timeout_secs

  if cmd_timeout is not None:
    if cmd_timeout <= 0:
      log.critical("The tests timeout must be greater than zero seconds!")
      sys.exit(1)

  if not os.path.exists(tests_folder):
    log.critical("The tests folder '{tests_folder}' doesn't seem to exist!".format(tests_folder = tests_folder))
    sys.exit(1)

  if not os.path.isdir(tests_folder):
    log.critical("The tests folder '{tests_folder}' doesn't seem to be a folder!".format(tests_folder = tests_folder))
    sys.exit(1)

  tests = parse_test_files(tests_folder, cmd_timeout)
  baseline = copy.deepcopy(SYSCALL_NAMES_ALL)
  syscall_count = len(baseline)
  keep_table = [ True for i in range(syscall_count) ]
  progress_template = "Testing syscall '{syscall_name}' - {idx}/{total}"

  for idx, x in enumerate(baseline):
    syscall_name = baseline[idx]

    if syscall_name not in SYSCALL_NAMES_MINIMAL:
      log.info(progress_template.format(syscall_name = syscall_name, idx = idx + 1, total = syscall_count))
      keep_table[idx] = False

      for test in tests:
        seccomp_profile = SeccompProfile(keep_table, baseline);
        save_seccomp_as_json(seccomp_profile, seccomp_file_dest)

        if not run_test_successfully(test):
          keep_table[idx] = True
          break

  log.info("Generating final seccomp-json security profile")
  seccomp_profile = SeccompProfile(keep_table, baseline);
  save_seccomp_as_json(seccomp_profile, seccomp_file_dest)

if __name__ == "__main__":
  main()

