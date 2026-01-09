use anyhow::{Context, Result, bail};
use std::env;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::mem::{self, MaybeUninit};
use std::ptr;
use url::Url;

const PAGE_SIZE: usize = 4096;
const ALIGN: usize = PAGE_SIZE - 1;

const EI_MAG0: usize = 0;
const EI_MAG1: usize = 1;
const EI_MAG2: usize = 2;
const EI_MAG3: usize = 3;
const EI_CLASS: usize = 4;
const EI_VERSION: usize = 6;

const ELFMAG0: u8 = 0x7f;
const ELFMAG1: u8 = b'E';
const ELFMAG2: u8 = b'L';
const ELFMAG3: u8 = b'F';

const EV_CURRENT: u8 = 1;

const Z_PROG: usize = 0;
const Z_INTERP: usize = 1;

// ----------------------------------------
// auxv support (always defined, stable)
// ----------------------------------------
#[cfg(target_os = "linux")]
mod auxv {
    #[repr(C)]
    #[derive(Copy, Clone)]
    pub struct Elf64_auxv_t {
        pub a_type: u64,
        pub a_un: Elf64_auxv_val,
    }

    #[repr(C)]
    #[derive(Copy, Clone)]
    pub union Elf64_auxv_val {
        pub a_val: u64,
        pub a_ptr: u64,
    }

    // libc crate doesn't always export `environ`, so declare it ourselves.
    unsafe extern "C" {
        pub static mut environ: *mut *mut libc::c_char;
    }
}

#[cfg(target_os = "linux")]
use auxv::Elf64_auxv_t;

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    if cfg!(not(target_pointer_width = "64")) {
        bail!("only 64-bit targets are supported");
    }
    if cfg!(not(target_arch = "x86_64")) {
        bail!("only x86_64 is supported");
    }

    let args: Vec<OsString> = env::args_os().collect();
    if args.len() < 2 {
        eprintln!("Usage: elf-rs <http[s]://example.com/binary> [args...]");
        bail!("missing ELF URL");
    }

    let url_os = &args[1];
    let url_str = os_to_str(url_os).context("URL must be valid UTF-8")?;
    let _ = Url::parse(url_str).context("invalid URL")?;

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("build http client")?;

    let mut response = client
        .get(url_str)
        .send()
        .context("failed to download ELF")?;

    let status = response.status();
    if !status.is_success() {
        bail!("unexpected HTTP status {}", status);
    }

    let mut image = Vec::new();
    response.copy_to(&mut image).context("read body")?;

    let (argv_ptr, auxv_ptr, sp) =
        locate_initial_stack(args.len()).context("failed to locate initial stack")?;

    z_entry_m(&image, argv_ptr, auxv_ptr, sp)
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<()> {
    bail!("this loader only supports Linux");
}

unsafe fn shift_stack_argv(sp: *mut usize, argv: *mut *mut libc::c_char, auxv: *mut Elf64_auxv_t) {
    let argc = *sp as usize;

    // Find end of auxv (AT_NULL entry included)
    let mut av = auxv;
    while (*av).a_type != libc::AT_NULL as u64 {
        av = av.add(1);
    }
    av = av.add(1); // one past AT_NULL, same as C (++av after loop)

    // byte span from argv[1] to end of auxv
    let src = argv.add(1) as *const u8;
    let dst = argv as *mut u8;
    let end = av as *const u8;
    let len = end as usize - src as usize;

    ptr::copy(src, dst, len);

    // argc--
    *sp = (argc - 1) as usize;
}

#[cfg(target_os = "linux")]
fn z_entry_m(
    elf_buf: &[u8],
    argv_ptr: *mut *mut libc::c_char,
    auxv_ptr: *mut Elf64_auxv_t,
    sp: *mut usize,
) -> Result<()> {
    let mut ehdrs: [libc::Elf64_Ehdr; 2] = unsafe { mem::zeroed() };
    let mut bases: [usize; 2] = [0; 2];
    let mut entries: [usize; 2] = [0; 2];
    let mut elf_interp: Option<CString> = None;

    let mut from_mem = true;

    for i in 0..2 {
        let ehdr = &mut ehdrs[i];
        if from_mem {
            *ehdr = read_struct::<libc::Elf64_Ehdr>(elf_buf, 0, "Elf_Ehdr")?;
            check_ehdr(ehdr)?;

            let phdrs = read_phdrs_from_mem(elf_buf, ehdr)?;
            bases[i] = loadelf_anon_m(elf_buf, ehdr, &phdrs)?;
            entries[i] = ehdr.e_entry as usize
                + if ehdr.e_type == libc::ET_DYN {
                    bases[i]
                } else {
                    0
                };

            for phdr in &phdrs {
                if phdr.p_type != libc::PT_INTERP {
                    continue;
                }
                if phdr.p_filesz != 0 {
                    bounds_check(
                        phdr.p_offset as usize,
                        phdr.p_filesz as usize,
                        elf_buf.len(),
                        "PT_INTERP bytes",
                    )?;
                }

                let start = phdr.p_offset as usize;
                let end = start + phdr.p_filesz as usize;
                let bytes = &elf_buf[start..end];
                if bytes.is_empty() || *bytes.last().unwrap() != 0 {
                    bail!("bogus interp path");
                }
                elf_interp = Some(
                    CStr::from_bytes_with_nul(bytes)
                        .context("invalid interp path")?
                        .to_owned(),
                );
            }

            if elf_interp.is_none() {
                break;
            }

            from_mem = false;
            continue;
        }

        let interp = elf_interp.as_ref().context("missing interp path")?;
        let fd = unsafe { libc::open(interp.as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("can't open interp");
        }

        let mut ehdr_buf = vec![0u8; mem::size_of::<libc::Elf64_Ehdr>()];
        read_exact_fd(fd, &mut ehdr_buf).context("can't read interp ELF header")?;
        *ehdr = read_struct::<libc::Elf64_Ehdr>(&ehdr_buf, 0, "Elf_Ehdr")?;
        check_ehdr(ehdr)?;

        let phdrs = read_phdrs_from_fd(fd, ehdr)?;
        bases[i] = loadelf_anon(fd, ehdr, &phdrs)?;
        entries[i] = ehdr.e_entry as usize
            + if ehdr.e_type == libc::ET_DYN {
                bases[i]
            } else {
                0
            };

        unsafe {
            libc::close(fd);
        }
        break;
    }

    // execfn_ptr should be argv[0], not argv itself
    let execfn_ptr = unsafe { *argv_ptr };

    patch_auxv(
        execfn_ptr,
        auxv_ptr,
        &ehdrs,
        &bases,
        &entries,
        elf_interp.is_some(),
    );

    let entry = if elf_interp.is_some() {
        entries[Z_INTERP]
    } else {
        entries[Z_PROG]
    };

    unsafe {
        shift_stack_argv(sp, argv_ptr, auxv_ptr);
    }
    unsafe { z_trampo(entry, sp) }
}

#[cfg(target_os = "linux")]
fn check_ehdr(ehdr: &libc::Elf64_Ehdr) -> Result<()> {
    let ident = &ehdr.e_ident;
    if ident[EI_MAG0] != ELFMAG0
        || ident[EI_MAG1] != ELFMAG1
        || ident[EI_MAG2] != ELFMAG2
        || ident[EI_MAG3] != ELFMAG3
    {
        bail!("bogus ELF header");
    }
    if ident[EI_CLASS] != libc::ELFCLASS64 as u8 {
        bail!("unsupported ELF class");
    }
    if ident[EI_VERSION] != EV_CURRENT {
        bail!("unsupported ELF version");
    }
    if ehdr.e_type != libc::ET_EXEC && ehdr.e_type != libc::ET_DYN {
        bail!("unsupported ELF type");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bounds_check(off: usize, len: usize, total: usize, what: &str) -> Result<()> {
    if off > total || len > total || off + len > total {
        bail!("ELF buffer out of bounds: {}", what);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_struct<T>(buf: &[u8], offset: usize, what: &str) -> Result<T> {
    let size = mem::size_of::<T>();
    bounds_check(offset, size, buf.len(), what)?;
    let mut out = MaybeUninit::<T>::uninit();
    unsafe {
        ptr::copy_nonoverlapping(buf.as_ptr().add(offset), out.as_mut_ptr() as *mut u8, size);
        Ok(out.assume_init())
    }
}

#[cfg(target_os = "linux")]
fn read_phdrs_from_mem(buf: &[u8], ehdr: &libc::Elf64_Ehdr) -> Result<Vec<libc::Elf64_Phdr>> {
    let count = ehdr.e_phnum as usize;
    let sz = count * mem::size_of::<libc::Elf64_Phdr>();
    bounds_check(ehdr.e_phoff as usize, sz, buf.len(), "Elf_Phdr table")?;
    let start = ehdr.e_phoff as usize;
    let end = start + sz;
    read_phdrs_from_slice(&buf[start..end], count)
}

#[cfg(target_os = "linux")]
fn read_phdrs_from_fd(fd: libc::c_int, ehdr: &libc::Elf64_Ehdr) -> Result<Vec<libc::Elf64_Phdr>> {
    let count = ehdr.e_phnum as usize;
    let sz = count * mem::size_of::<libc::Elf64_Phdr>();
    let mut buf = vec![0u8; sz];
    let off = ehdr.e_phoff as libc::off_t;
    let rc = unsafe { libc::lseek(fd, off, libc::SEEK_SET) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("can't lseek to program header");
    }
    read_exact_fd(fd, &mut buf).context("can't read program header")?;
    read_phdrs_from_slice(&buf, count)
}

#[cfg(target_os = "linux")]
fn read_phdrs_from_slice(buf: &[u8], count: usize) -> Result<Vec<libc::Elf64_Phdr>> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * mem::size_of::<libc::Elf64_Phdr>();
        out.push(read_struct::<libc::Elf64_Phdr>(buf, off, "Elf_Phdr")?);
    }
    Ok(out)
}

#[cfg(target_os = "linux")]
fn loadelf_anon_m(
    buf: &[u8],
    ehdr: &libc::Elf64_Ehdr,
    phdrs: &[libc::Elf64_Phdr],
) -> Result<usize> {
    let mut minva = usize::MAX;
    let mut maxva = 0usize;
    for phdr in phdrs {
        if phdr.p_type != libc::PT_LOAD {
            continue;
        }
        if phdr.p_filesz != 0 {
            bounds_check(
                phdr.p_offset as usize,
                phdr.p_filesz as usize,
                buf.len(),
                "PT_LOAD bytes",
            )?;
        }
        minva = minva.min(phdr.p_vaddr as usize);
        maxva = maxva.max((phdr.p_vaddr + phdr.p_memsz) as usize);
    }

    minva = trunc_pg(minva);
    maxva = round_pg(maxva);

    let dyn_elf = ehdr.e_type == libc::ET_DYN;
    let hint = if dyn_elf {
        ptr::null_mut()
    } else {
        minva as *mut _
    };
    let mut flags = if dyn_elf { 0 } else { libc::MAP_FIXED };
    flags |= libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    let base = unsafe { libc::mmap(hint, maxva - minva, libc::PROT_NONE, flags, -1, 0) };
    if base == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).context("mmap failed");
    }
    unsafe {
        libc::munmap(base, maxva - minva);
    }

    let base_addr = base as usize;
    let flags = libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

    for phdr in phdrs {
        if phdr.p_type != libc::PT_LOAD {
            continue;
        }
        let off = (phdr.p_vaddr as usize) & ALIGN;
        let mut start = if dyn_elf { base_addr } else { 0 };
        start += trunc_pg(phdr.p_vaddr as usize);
        let sz = round_pg(phdr.p_memsz as usize + off);

        let p = unsafe { libc::mmap(start as *mut _, sz, libc::PROT_WRITE, flags, -1, 0) };
        if p == libc::MAP_FAILED {
            unsafe {
                libc::munmap(base as *mut _, maxva - minva);
            }
            return Err(std::io::Error::last_os_error()).context("mmap segment failed");
        }

        let dst = unsafe { (p as *mut u8).add(off) };
        if phdr.p_filesz != 0 {
            let start_off = phdr.p_offset as usize;
            unsafe {
                ptr::copy_nonoverlapping(buf.as_ptr().add(start_off), dst, phdr.p_filesz as usize);
            }
        }
        if phdr.p_memsz > phdr.p_filesz {
            let diff = (phdr.p_memsz - phdr.p_filesz) as usize;
            unsafe {
                ptr::write_bytes(dst.add(phdr.p_filesz as usize), 0, diff);
            }
        }

        let rc = unsafe { libc::mprotect(p, sz, pflags(phdr.p_flags)) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("mprotect failed");
        }
    }

    Ok(base_addr)
}

#[cfg(target_os = "linux")]
fn loadelf_anon(
    fd: libc::c_int,
    ehdr: &libc::Elf64_Ehdr,
    phdrs: &[libc::Elf64_Phdr],
) -> Result<usize> {
    let mut minva = usize::MAX;
    let mut maxva = 0usize;
    for phdr in phdrs {
        if phdr.p_type != libc::PT_LOAD {
            continue;
        }
        minva = minva.min(phdr.p_vaddr as usize);
        maxva = maxva.max((phdr.p_vaddr + phdr.p_memsz) as usize);
    }

    minva = trunc_pg(minva);
    maxva = round_pg(maxva);

    let dyn_elf = ehdr.e_type == libc::ET_DYN;
    let hint = if dyn_elf {
        ptr::null_mut()
    } else {
        minva as *mut _
    };
    let mut flags = if dyn_elf { 0 } else { libc::MAP_FIXED };
    flags |= libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    let base = unsafe { libc::mmap(hint, maxva - minva, libc::PROT_NONE, flags, -1, 0) };
    if base == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).context("mmap failed");
    }
    unsafe {
        libc::munmap(base, maxva - minva);
    }

    let base_addr = base as usize;
    let flags = libc::MAP_FIXED | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

    for phdr in phdrs {
        if phdr.p_type != libc::PT_LOAD {
            continue;
        }
        let off = (phdr.p_vaddr as usize) & ALIGN;
        let mut start = if dyn_elf { base_addr } else { 0 };
        start += trunc_pg(phdr.p_vaddr as usize);
        let sz = round_pg(phdr.p_memsz as usize + off);

        let p = unsafe { libc::mmap(start as *mut _, sz, libc::PROT_WRITE, flags, -1, 0) };
        if p == libc::MAP_FAILED {
            unsafe {
                libc::munmap(base as *mut _, maxva - minva);
            }
            return Err(std::io::Error::last_os_error()).context("mmap segment failed");
        }

        let off64 = phdr.p_offset as libc::off_t;
        if unsafe { libc::lseek(fd, off64, libc::SEEK_SET) } < 0 {
            return Err(std::io::Error::last_os_error()).context("lseek failed");
        }

        let dst = unsafe { (p as *mut u8).add(off) };
        if phdr.p_filesz != 0 {
            read_exact_fd(fd, unsafe {
                std::slice::from_raw_parts_mut(dst, phdr.p_filesz as usize)
            })
            .context("read segment failed")?;
        }

        let rc = unsafe { libc::mprotect(p, sz, pflags(phdr.p_flags)) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("mprotect failed");
        }
    }

    Ok(base_addr)
}

#[cfg(target_os = "linux")]
fn pflags(flags: u32) -> i32 {
    let mut prot = 0;
    if flags & libc::PF_R as u32 != 0 {
        prot |= libc::PROT_READ;
    }
    if flags & libc::PF_W as u32 != 0 {
        prot |= libc::PROT_WRITE;
    }
    if flags & libc::PF_X as u32 != 0 {
        prot |= libc::PROT_EXEC;
    }
    prot
}

#[cfg(target_os = "linux")]
fn round_pg(value: usize) -> usize {
    (value + ALIGN) & !ALIGN
}

#[cfg(target_os = "linux")]
fn trunc_pg(value: usize) -> usize {
    value & !ALIGN
}

#[cfg(target_os = "linux")]
fn read_exact_fd(fd: libc::c_int, buf: &mut [u8]) -> Result<()> {
    let mut read_total = 0;
    while read_total < buf.len() {
        let rc = unsafe {
            libc::read(
                fd,
                buf[read_total..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - read_total,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("read failed");
        }
        if rc == 0 {
            bail!("unexpected EOF");
        }
        read_total += rc as usize;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn locate_initial_stack(
    argc: usize,
) -> Result<(*mut *mut libc::c_char, *mut Elf64_auxv_t, *mut usize)> {
    let envp = unsafe { auxv::environ };
    if envp.is_null() {
        bail!("environ is null");
    }

    // argv is located directly before envp on the initial stack layout
    let argv = unsafe { envp.offset(-((argc + 1) as isize)) };
    let sp = unsafe { argv.offset(-1) } as *mut usize;

    let mut env_iter = envp;
    unsafe {
        while !(*env_iter).is_null() {
            env_iter = env_iter.add(1);
        }
    }

    let auxv = unsafe { env_iter.add(1) as *mut Elf64_auxv_t };
    Ok((argv, auxv, sp))
}

#[cfg(target_os = "linux")]
fn patch_auxv(
    execfn_ptr: *mut libc::c_char,
    auxv_ptr: *mut Elf64_auxv_t,
    ehdrs: &[libc::Elf64_Ehdr; 2],
    bases: &[usize; 2],
    entries: &[usize; 2],
    has_interp: bool,
) {
    let mut av = auxv_ptr;
    unsafe {
        while (*av).a_type != libc::AT_NULL as u64 {
            match (*av).a_type as libc::c_ulong {
                libc::AT_PHDR => {
                    (*av).a_un.a_val = (bases[Z_PROG] + ehdrs[Z_PROG].e_phoff as usize) as u64;
                }
                libc::AT_PHNUM => {
                    (*av).a_un.a_val = ehdrs[Z_PROG].e_phnum as u64;
                }
                libc::AT_PHENT => {
                    (*av).a_un.a_val = ehdrs[Z_PROG].e_phentsize as u64;
                }
                libc::AT_ENTRY => {
                    (*av).a_un.a_val = entries[Z_PROG] as u64;
                }
                libc::AT_EXECFN => {
                    (*av).a_un.a_val = execfn_ptr as u64;
                }
                libc::AT_BASE => {
                    if has_interp {
                        (*av).a_un.a_val = bases[Z_INTERP] as u64;
                    }
                }
                _ => {}
            }
            av = av.add(1);
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn z_trampo(entry: usize, sp: *mut usize) -> ! {
    unsafe {
        core::arch::asm!(
            "mov rsp, {sp}",
            "jmp {entry}",
            sp = in(reg) sp,
            entry = in(reg) entry,
            options(noreturn)
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
unsafe fn z_trampo(entry: usize, sp: *mut usize) -> ! {
    unsafe {
        core::arch::asm!(
            "mov sp, {sp}",
            "br {entry}",
            sp = in(reg) sp,
            entry = in(reg) entry,
            options(noreturn)
        );
    }
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
unsafe fn z_trampo(_entry: usize, _sp: *mut usize) -> ! {
    core::intrinsics::abort()
}

fn os_to_str(value: &OsStr) -> Result<&str> {
    value.to_str().context("value must be UTF-8")
}
