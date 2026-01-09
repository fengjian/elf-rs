# elf-rs

Run remote Linux ELF binaries directly from memory.
Rust port of [MikhailProg/elf](https://github.com/MikhailProg/elf.git): download an ELF over HTTP(S), map it in memory, patch auxv/argv, and jump to its entry point without writing to disk.

`elf-rs` downloads a Linux ELF executable over **HTTP(S)**, maps it into memory using `mmap`, patches the initial process `auxv` entries, fixes `argv`/`argc` so arguments are correctly forwarded, and finally transfers control to the ELF entry point (or its PT_INTERP dynamic linker).

This makes the loaded program behave like it was executed normally via `execve`, but **without writing the executable to disk**.

---

## Features

- ✅ Download & run ELF binaries from **HTTP(S)** URLs
- ✅ Loads ELF **directly from memory** (no temp file)
- ✅ Supports both:
  - **statically linked** ELF (no PT_INTERP)
  - **dynamically linked** ELF (PT_INTERP → loads system dynamic linker)
- ✅ Correctly patches important `auxv` entries:
  - `AT_PHDR`, `AT_PHNUM`, `AT_PHENT`, `AT_ENTRY`, `AT_EXECFN`, `AT_BASE`
- ✅ Correctly forwards program arguments:
  - `elf-rs <url> [args...]` → loaded program receives `[args...]`
- ✅ Works on:
  - `x86_64-unknown-linux-gnu`
  - `aarch64-unknown-linux-gnu`
- ✅ Optional: disable HTTPS certificate validation (useful for internal testing)

---

## How it works (high-level)

1. Download ELF bytes into memory
2. Parse ELF header + program headers (PT_LOAD segments, optional PT_INTERP)
3. `mmap` each PT_LOAD into the correct virtual memory location
4. If PT_INTERP exists: load the interpreter ELF (dynamic loader) too
5. Patch initial stack vectors (`auxv`) so the dynamic linker and libc see correct metadata
6. Shift `argv` and decrement `argc` so the loaded program sees the intended args
7. Jump to entry point with a trampoline (`jmp`/`br`) while restoring the original stack pointer

---

## Usage

```bash
elf-rs <http[s]://host/path/to/binary> [args...]
```

## Example:

```bash
./elf-rs https://example.com/hello -f --verbose
```

## The loaded ELF program receives:
```
argv[0] = "hello"
argv[1] = "-f"
argv[2] = "--verbose"

```

## build

```bash
cargo build --release
```


