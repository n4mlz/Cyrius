<h1 align="center">
<img src="assets/cyrius.png" alt="cyrius" width="300"/>
</h1>

<p align="center" style="display: flex; gap: 10px; justify-content: center; align-items: center;">
    <a href="https://github.com/n4mlz/Cyrius/actions/workflows/test.yml">
        <img src="https://github.com/n4mlz/Cyrius/actions/workflows/test.yml/badge.svg" alt="CI">
    </a>
    <a href="https://opensource.org/licenses/Apache-2.0">
        <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License">
    </a>
    <a href="https://deepwiki.com/n4mlz/Cyrius">
        <img src="https://deepwiki.com/badge.svg?repo=n4mlz/Cyrius" alt="DeepWiki">
    </a>
</p>

Cyrius is a container-focused operating system that runs OCI containers natively, without depending on the Linux kernel. Cyrius treats containers as first-class OS entities and manages their lifecycle and isolation directly.

For implementation-oriented documentation and code-level explanations, see DeepWiki:
https://deepwiki.com/n4mlz/Cyrius

## 🧭 Overview

Linux containers are effective, but the kernel does not treat “container” as a native concept. In many systems, container lifecycle and state are maintained indirectly via user-space bookkeeping.

Cyrius explores an alternative model: containers are explicit OS-managed objects, and container operations are expressed as container operations.

## ❓ Why Cyrius

Cyrius is motivated by practical friction points that appear when containers are represented as “processes with attributes”:

- Isolation and visibility can rely on cross-subsystem interfaces with subtle dependencies.
- The security model can become difficult to reason about when built from many separate features.
- Container state can become coupled to user-space runtimes keeping critical handles alive.

Cyrius aims to make the container environment a durable, OS-managed entity rather than an emergent property of a running process.

## 🧩 Design principles

1. Containers are first-class OS objects  
   A container is an explicit entity representing an execution environment. The OS tracks its lifecycle and state.

2. Environment-first model  
   Creating an environment and starting a process within it are separate steps (“create then start”).

3. Minimal host interface, container-native operations  
   The host-side interface focuses on container management (create/start/stop), avoiding long chains of low-level setup steps.

4. Compatibility where it matters  
   Cyrius targets Linux syscall compatibility sufficient for typical container workloads, but does not aim for full Linux feature parity.

5. Deliberate scope constraints  
   Cyrius assumes a two-world model (host world and container world) and does not treat nested containers as a primary goal.

## 🧪 Status and scope

Cyrius is experimental and under active development. Interfaces and behavior may change.

Targets:

- Native execution of OCI bundles (runtime config + root filesystem)
- OS-managed container lifecycle
- A pragmatic subset of Linux syscall compatibility for container workloads

Non-targets (for now):

- General-purpose desktop/server usage
- Full parity with all Linux system calls and Linux container-specific features
- Nested containers as a primary design goal

## 🚀 Quick start

### Requirements

Rust toolchain:

- Rust nightly: `nightly-2025-09-04`
- Components: `rust-src`, `rustfmt`, `clippy`, `llvm-tools-preview`
- Targets: `x86_64-unknown-none`, `x86_64-unknown-uefi`

Runtime:

- `qemu-system-x86_64`

Optional (for preparing OCI bundles on your development machine):

- `skopeo`
- `umoci`

### Build and run

```sh
$ cargo xtask run --release
```

## 📦 Running an OCI bundle (example)

The following example shows a typical flow:

1. prepare an OCI bundle (BusyBox in this case), and
2. boot Cyrius and run the bundle using the built-in OCI runtime interface.

### 1) Prepare the bundle (on your development machine)

This project includes a helper script that creates an OCI bundle. It expects `./mnt` to contain `busybox.tar`.

```
$ ./make_bundle.sh
Getting image source signatures
Copying blob 5bfa213ad291 done   |
Copying config ff7d91a4de done   |
Writing manifest to image destination
```

### 2) Boot Cyrius and run the container

```
$ cargo xtask run --release
(omitted)
INFO : Jumping to kernel entry point at VirtAddr(0x100000a5d10)
[blk] discovered 1 virtio block device(s)
[net] discovered 1 virtio network device(s)
[vfs] mounted FAT32 at /mnt from virtio-blk0 (1163002 blocks)
[kernel] scheduler started
   _____           _
  / ____|         (_)
 | |    _   _ _ __ _ _   _ ___
 | |   | | | | '__| | | | / __|
 | |___| |_| | |  | | |_| \__ \
 \_____|\__, |_|  |_|\__,_|___/
         __/ |
        |___/

[timer] first tick
[web] echo server listening on 0.0.0.0:12345
[shell] ready; type `help` for command list
```

In the Cyrius shell:

```
$ ls
d 0 mnt

$ tar mnt/busybox.tar bundle
$ ls bundle
 3181 config.json
d 0 rootfs

$ oci-runtime create some_container bundle
container some_container created

$ oci-runtime state some_container
{"annotations":{"org.opencontainers.image.architecture":"amd64","org.opencontainers.image.author":"","org.opencontainers.image.created":"2024-09-26T21:31:42Z","org.opencontainers.image.exposedPorts":"","org.opencontainers.image.os":"linux","org.opencontainers.image.stopSignal":""},"bundle":"/bundle","id":"some_container","ociVersion":"1.0.0","pid":null,"status":"created"}

$ oci-runtime start some_container
/ # ls
bin   dev   etc   home  proc  root  sys   tmp   usr   var
/ # uname -a
Linux umoci-default 0.0.1-alpha cyrius x86_64 GNU/Linux
/ # whoami
root
/ # echo "Hello world, from Linux container!"
Hello world, from Linux container!
/ # exit
```

## 🛠️ Development

This repository uses `cargo xtask` to keep build, run, and test workflows consistent.

Common commands:

```sh
# Run (release)
$ cargo xtask run --release

# Test
$ cargo xtask test
```

If you are new to this codebase, start with:

- the top-level build/run workflow (`cargo xtask run`)
- the DeepWiki pages for boot flow, syscall handling, and container lifecycle design

## 📚 Documentation

- DeepWiki (implementation-focused): [https://deepwiki.com/n4mlz/Cyrius](https://deepwiki.com/n4mlz/Cyrius)
- Repository Wiki (design notes, higher-level documentation): (add link once published)

## 📄 License

Cyrius is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
