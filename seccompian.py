#!/usr/bin/env python3

import os
import sys
import argparse
import copy
import subprocess
import json

APP_VERSION = "0.0.1"

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
  "futex",
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

    for idx, x in enumerate(keep_table):
      if x:
        self.names.append(baseline[idx])

class SeccompProfile:
  def __init__(self, keep_table, baseline):
    self.defaultAction = "SCMP_ACT_ERRNO"
    self.syscalls = [Syscalls(keep_table, baseline)]

  def toJSON(self):
    return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)

def save_seccomp_as_json(seccomp_profile, dest_file):
  json_string = seccomp_profile.toJSON()

  with open(dest_file, 'w') as f:
    f.write(json_string)

class Test:
  def __init__(self, command_and_arguments):
    self.command_and_arguments = command_and_arguments

def run_test_successfully(cmd):
  cmdline = cmd.command_and_arguments
  print("Running command:", cmdline)

  with subprocess.Popen(cmdline, stdout=subprocess.PIPE, bufsize=1, universal_newlines=True) as p:
    for line in p.stdout:
      print(line, end='') # process line here

  return p.returncode == 0

def make_true_bools(count):
  ret = []

  for i in range(0, count):
    ret.append(True)

  return ret

def parse_test_files(tests_folder):
  tests = []

  for file in os.listdir(tests_folder):
    if file.endswith(".test"):
      test = parse_test_file(os.path.join(tests_folder, file))
      tests.append(test)

  return tests

def parse_test_file(test_file):
  test_args = []

  with open(test_file, 'r') as f:
    for line in f.readlines():
      test_args.append(line.strip())

  if len(test_args) == 0:
    raiseRuntimeError("No command or arguments found in test file '{test_file}".format(test_file = test_file))

  return Test(test_args)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--tests-folder", type=str, required=True)
  parser.add_argument("--seccomp-file-dest", type=str, required=True)
  parser.add_argument("--version", action="version", version="%(prog)s " + APP_VERSION)

  args = parser.parse_args()
  seccomp_file_dest = args.seccomp_file_dest
  tests_folder = args.tests_folder

  if not os.path.exists(tests_folder):
    print("The tests folder '{tests_folder}' doesn't seem to exist!".format(tests_folder = tests_folder), file = sys.stderr)
    sys.exit(1)

  if not os.path.isdir(tests_folder):
    print("The tests folder '{tests_folder}' doesn't seem to be a folder!".format(tests_folder = tests_folder), file = sys.stderr)
    sys.exit(1)

  tests = parse_test_files(tests_folder)
  baseline = copy.deepcopy(SYSCALL_NAMES_ALL)
  syscall_count = len(baseline)
  keep_table = make_true_bools(syscall_count)

  for idx, x in enumerate(baseline):
    syscall_name = baseline[idx]

    if syscall_name not in SYSCALL_NAMES_MINIMAL:
      print("\n>>>>>>> Testing syscall '{syscall_name}' - {idx}/{total}".format(syscall_name = syscall_name, idx = idx + 1, total = syscall_count))
      keep_table[idx] = False
      failed = False

      for test in tests:
        seccomp_profile = SeccompProfile(keep_table, baseline);
        save_seccomp_as_json(seccomp_profile, seccomp_file_dest)

        if not run_test_successfully(test):
          failed = True
          break

      if failed:
        keep_table[idx] = True

  print("Generating file seccomp security profile")
  seccomp_profile = SeccompProfile(keep_table, baseline);
  save_seccomp_as_json(seccomp_profile, seccomp_file_dest)

if __name__ == "__main__":
  main()

