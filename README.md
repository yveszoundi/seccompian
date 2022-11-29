# What is this?

`seccompian` is a brute force tool for [seccomp]() profile generation. 

- The tool attempts to generate a `seccomp` security profile based on `simulated runs` (test datasets following the `happy path`).
- The main use-case is one-of processes running inside Docker

The great thing about brute-force is that you don't need to be smart, as long as you can wait just a little bit...

# Why this?

I needed to generate a `seccomp` security profile for a container image (amd64 and arm64 platforms).

- For `arm64`, I was able to easily generate a file on amd64 via [oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook.git)
- For `arm64`, I struggled with tooling running inside QEMU from an amd64 host machine (obscure errors)

After investigating tooling and trying to make sense of errors, I was like "pure brute-force does sometimes work...".

# How does this work?

There are 4 key logical steps:

- Define your tests (happy paths), those need to be representative enough of your entire application features
- Enumerate all valid `syscalls`
- For each `syscall`, try disabling it while running tests
  - Generate a `seccomp` file with the current `syscall` disabled
  - If the container process terminates with errors, allow the `syscall`
  - Otherwise it means that we can safely discard, while generating the next `seccomp` file
- Generate the final `seccomp` security profile JSON file


# How to contribute?

The best way to contribute is via a pull request.

Please note that I don't write that much code professionally anymore and I haven't written any "real" Python application since the early 2000's.
