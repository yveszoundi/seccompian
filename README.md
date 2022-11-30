THIS IS STILL WORK IN PROGRESS!!

# What is this?

`seccompian` is a brute force tool for [seccomp]() profile generation (`Python 3`). 

- The tool attempts to generate a `seccomp` security profile based on `simulated runs` (test datasets following the `happy path`)
- The main use-case is one-of processes running inside a container engine (i.e., [Docker](https://www.docker.com/), [Podman](https://podman.io/))

The great thing about brute-force is that you don't need to be smart, as long as you can wait just a little bit...

# Why this?

I needed to generate a `seccomp` security profile for a container image (`amd64` and `arm64` platforms).

- For `amd64`, I was able to easily generate a file on `amd64` via [oci-seccomp-bpf-hook](https://github.com/containers/oci-seccomp-bpf-hook.git)
- For `arm64`, I struggled with tooling running inside [QEMU](https://www.qemu.org/) from an `amd64` host machine (obscure errors, coupled with overall slowness of emulated `arm64` on `amd64`)

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

# How to use it

## Displaying the options

```
$ python3 seccompian.py -h
usage: seccompian.py [-h] --tests-folder TESTS_FOLDER --seccomp-file-dest SECCOMP_FILE_DEST [--version]

options:
  -h, --help            show this help message and exit
  --tests-folder TESTS_FOLDER
  --seccomp-file-dest SECCOMP_FILE_DEST
  --version             show program's version number and exit
```

## Sample usage

The command below will run sample tests from the folder `./example/tests`. The final `seccomp` security profile will be created in `./example/generated/profile.json`.

**IMPORTANT**: Please edit the `test.test` file in `./examples/tests` to reflect the location of the json file and the container command to run!

```
python3 seccompian.py --tests-folder ./example/tests --seccomp-file-dest ./example/generated/profile.json
```

Please consult the `example/tests` folder for more details: essentially you put the command and arguments to run in separate lines inside a file with the `.test` extension.

# How to contribute?

The best way to contribute is via [pull requests](https://github.com/yveszoundi/seccompian/pulls).

I haven't written any "real" Python application since the early 2000's, but here are the main reasons for using Python in this project:

- Python3 is usually installed on most Linux or Unix-like machines (Mac OS, BSD)
- The code is just about getting things done as "quickly" as possible ("programming-wise")
- Speed doesn't matter that much as we're running mostly shell commands (note: we're not doing anything "in parallel")

# References

- https://docs.docker.com/engine/security/seccomp/
- https://github.com/microsoft/docker/blob/master/docs/security/seccomp.md
- https://kubernetes.io/docs/tutorials/security/seccomp/
- https://man7.org/linux/man-pages/man2/seccomp.2.html
