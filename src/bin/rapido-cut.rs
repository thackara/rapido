// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE LLC
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::env;
use std::fs;
use std::io;
use std::io::Seek;
use std::io::Write;
use std::path::{self, Path, PathBuf, Component};
use elf::abi;
use elf::ElfStream;
use elf::endian::AnyEndian;

use crosvm::argument::{self, Argument};
mod kmod;
use kmod::kmod_context::{KmodContext, ModuleStatus};
extern crate kv_conf;

// Don't print debug messages on release builds...
#[cfg(debug_assertions)]
macro_rules! dout {
    ($($l:tt)*) => { println!($($l)*); }
}
#[cfg(not(debug_assertions))]
macro_rules! dout {
    ($($l:tt)*) => {};
}

struct Fsent {
    path: PathBuf,
    md: fs::Metadata,
}

const BIN_PATHS: [&str; 2] = [ "/usr/bin", "/usr/sbin" ];
const LIB_PATHS: [&str; 2] = [ "/usr/lib64", "/usr/lib" ];

// We *should* be running as an unprivileged process, so don't filter or block
// access to parent or special paths; this should all be handled by the OS.
fn path_stat(name: &str, search_paths: &[&str]) -> Option<Fsent> {
    dout!("resolving path for {:?}", name);
    // if name has any separator in it then we should handle it as a relative
    // or absolute path. This should be close enough as a check.
    if name.contains(std::path::MAIN_SEPARATOR_STR) {
        dout!("using relative / absolute path {:?} as-is", name);
        return match fs::symlink_metadata(name) {
            Ok(md) => Some(Fsent {
                path: path::absolute(name).expect("absolute failed for good path"),
                md: md
            }),
            Err(_) => None,
        }
    }

    // TODO: search all paths and prefer non-symlink if multiple?
    for dir in search_paths.iter() {
        let p = PathBuf::from(dir).join(name);
        let md = fs::symlink_metadata(&p);
        if md.is_ok() {
            return Some(Fsent {path: p, md: md.unwrap()});
        }
    }

    None
}

// Parse ELF NEEDED entries to gather shared object dependencies
// This function intentionally ignores any DT_RPATH paths.
fn elf_deps(f: &fs::File, path: &Path, dups_filter: &mut HashMap<String, u64>) -> Result<Vec<(String, Option<String>)>, io::Error> {
    let mut ret: Vec<(String, Option<String>)> = vec![];

    let mut file = match ElfStream::<AnyEndian, _>::open_stream(f) {
        Ok(f) => f,
        Err(e) => {
            // ParseError::BadOffset / ParseError::BadMagic is returned
            // immediately for empty / non-elf, which we want to ignore.
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    e.to_string()));
        },
    };

    let dynamics = match file.dynamic() {
        Ok(d) => {
            if d.is_none() {
                dout!("Failed to find .dynamic for {:?}", path);
                return Ok(ret);
            }
            d.unwrap()
        },
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        },
    };

    let dyna_offs: Vec<usize> = dynamics.iter()
        .filter_map(|dyna| {
            if dyna.d_tag != abi::DT_NEEDED {
                return None;
            }
            let str_off: usize = dyna.d_val().try_into()
                .expect("failed to get dyna offset");
            Some(str_off)
        })
        .collect();

    let dynsyms_strs = match file.dynamic_symbol_table() {
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        },
        Ok(tup) => {
            if tup.is_none() {
                dout!("no tables for {:?}", path);
                return Ok(ret);
            }
            let (_, strs) = tup.unwrap();
            strs
        },
    };

    for str_off in dyna_offs {
        match dynsyms_strs.get(str_off) {
            Ok(sraw) => {
                let s = sraw.to_string();
                if *dups_filter.entry(s.clone()).and_modify(|s| *s += 1).or_insert(1) == 1 {
                    dout!("new elf dependency({:?}): {:?}", str_off, s);
                    ret.push((s, None));
                } else {
                    dout!("duplicate elf dependency({:?}): {:?}", str_off, sraw);
                }
            },
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData,
                        e.to_string()));
            },
        };
    }

    Ok(ret)
}

// XXX: symlinks in parent ancestry will be archived as dirs
// FIXME: how does this handle relative "" parents?
fn gather_archive_dirs<W: Seek + Write>(
    path: Option<&Path>,
    parent_dirs_amd: &cpio::ArchiveMd,
    paths_seen: &mut HashMap<PathBuf, u64>,
    cpio_state: &mut cpio::ArchiveState,
    mut cpio_writer: W,
) -> io::Result<()> {
    // path may come from parent(), hence Option
    let p = match path {
        None => return Ok(()),
        // don't canonicalize dirs: dest path may not match host
        Some(p) => p,
    };

    // path_stat() and dst assignment call absolute()
    if !p.is_absolute() {
        panic!("non-absolute path, check path_stat and dst paths");
    }

    if paths_seen.get(p).is_some() {
        dout!("ignoring seen directory and parents: {:?}", p);
        return Ok(());
    }
    let mut here = PathBuf::from("/");

    // order is important: parent dirs must be archived before children
    for comp in p.components() {
        match comp {
            Component::RootDir => continue,
            Component::CurDir | Component::ParentDir => {
                panic!("got CurDir or ParentDir after canonicalization");
            },
            Component::Prefix(_) => {
                eprintln!("non-Unix path prefixes not supported");
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            },
            Component::Normal(c) => here.push(c),
        }

        if *paths_seen.entry(here.clone()).and_modify(|s| *s += 1).or_insert(1) > 1 {
            dout!("ignoring seen directory: {:?}", here);
            continue;
        }

        cpio::archive_path(cpio_state, &here, &parent_dirs_amd, &mut cpio_writer)?;
        println!("archived dir: {:?}", here);
    }

    Ok(())
}

fn gather_archive_file<W: Seek + Write>(
    src: &Path,
    dst: &Path,
    amd: &cpio::ArchiveMd,
    mode_mask: Option<u32>,
    libs_names: &mut Vec<(String, Option<String>)>,
    libs_seen: &mut HashMap<String, u64>,
    cpio_state: &mut cpio::ArchiveState,
    mut cpio_writer: W,
) -> io::Result<()> {
    let mut f = fs::OpenOptions::new().read(true).open(src)?;
    if mode_mask.is_none() || mode_mask.unwrap() & amd.mode != 0 {
        match elf_deps(&f, src, libs_seen) {
            Ok(mut d) => libs_names.append(&mut d),
            Err(ref e) if e.kind() == io::ErrorKind::InvalidInput => {
                dout!("executable {:?} not an elf", src);
            },
            Err(e) => {
                dout!("failed to obtain dependencies for elf {:?}: {:?}", src, e);
            },
        }
    }
    // don't check for '#!' interpreters like Dracut, it's messy

    f.seek(io::SeekFrom::Start(0))?;
    cpio::archive_file(cpio_state, dst, &amd, &f, &mut cpio_writer)?;

    Ok(())
}

fn archive_kmod_path<W: Seek + Write>(
    src: &Path,
    dst: &Path,
    cpio_state: &mut cpio::ArchiveState,
    cpio_writer: W,
) -> io::Result<()> {
    let md = fs::symlink_metadata(src)?;
    let archive_md = cpio::ArchiveMd::from(cpio_state, &md)?;
    let kmod_f = fs::File::open(src)?;
    cpio::archive_file(
        cpio_state,
        dst,
        &archive_md,
        &kmod_f,
        cpio_writer,
    )?;
    println!("archived kmod: {:?} -> {:?}", src, dst);
    Ok(())
}

// Linux version 6.17.0-2-default ...
fn get_host_rel(kvers: &[u8]) -> io::Result<&str> {

    match str::from_utf8(kvers) {
        Err(_) => Err(io::Error::from(io::ErrorKind::InvalidData)),
        Ok(s) => match s.strip_prefix("Linux version ") {
            None => Err(io::Error::from(io::ErrorKind::InvalidData)),
            Some(rel) => match rel.split_once([' ']) {
                Some((rel, _)) => Ok(rel),
                None => Err(io::Error::from(io::ErrorKind::InvalidData)),
            },
        },
    }
}

fn args_usage(params: &[Argument]) {
    argument::print_help("rapido-cut", "OUTPUT", params);
}

fn args_process(
    inst: &mut Vec<(String, Option<String>)>,
    kmods_out: &mut Vec<(String, Option<String>)>,
) -> argument::Result<PathBuf> {
    let params = &[
        Argument::positional("OUTPUT", "Write initramfs archive to this file path."),
        Argument::value(
            "install",
            "FILES",
            "List of files to archive. Space separated with <src>→<dest> support."
        ),
        Argument::value(
            "install-kmod",
            "MODULES",
            "space separated list of kernel modules to install with dependencies.",
        ),
        Argument::short_flag('h', "help", "Print help message."),
    ];

    let mut positional_args = 0;
    let args = env::args().skip(1); // skip binary name
    let match_res = argument::set_arguments(args, params, |name, value| {
        match name {
            "" => positional_args += 1,
            "install" => {
                for file in value.unwrap().split(' ') {
                    let file_parsed = match file.split_once('→') {
                        // source only
                        None => (file.to_string(), None),
                        // source→dest
                        Some((s, d)) if s == "" || d == "" => {
                            return Err(argument::Error::InvalidValue {
                                value: file.to_owned(),
                                expected: String::from("empty source or dest"),
                            });
                        },
                        Some((s, d)) => (s.to_string(), Some(d.to_string())),
                    };
                    inst.push(file_parsed);
                }
            }
            "install-kmod" => {
                let kmod_parsed: argument::Result<Vec<(String, Option<String>)>> = value
                    .unwrap()
                    .split(' ')
                    .map(|f| {
                        f.parse().map(|s| (s, None)).map_err(|_| argument::Error::InvalidValue {
                            value: f.to_owned(),
                            expected: String::from("MODULES must be utf-8 strings"),
                        })
                    })
                    .collect();
                kmods_out.append(&mut kmod_parsed?);
            }
            "help" => return Err(argument::Error::PrintHelp),
            _ => unreachable!(),
        };
        Ok(())
    });

    match match_res {
        Ok(_) => {
            if positional_args != 1 {
                args_usage(params);
                return Err(argument::Error::ExpectedArgument(
                    "one OUTPUT parameter required".to_string(),
                ));
            }
        }
        Err(e) => {
            args_usage(params);
            return Err(e);
        }
    }

    let last_arg = env::args_os().last().unwrap();
    Ok(PathBuf::from(&last_arg))
}

fn main() -> io::Result<()> {
    struct Gather {
        // The names tuple is (host-source-path, Option<initramfs-destination).
        // If Option is None then the destination path will match the source.
        // Dependencies (elf, kmod, etc.) are added to the end of the gather
        // list as they are found.
        names: Vec<(String, Option<String>)>,
        // offset that we are currently processing
        off: usize,
        // @names offset which couldn't be found
        missing: Vec<usize>,
    }

    struct State {
        bins: Gather,
        libs: Gather,
        kmods: Gather,
        // TODO: data: Gather,  // don't check for elf deps? or just rename "bins" to "files" and
    }

    let mut state = State {
        bins: Gather {
            names: vec!(),
            off: 0,
            missing: vec!(),
        },
        libs: Gather {
            names: vec!(),
            off: 0,
            missing: vec!(),
        },
        kmods: Gather {
            names: vec!(),
            off: 0,
            missing: vec!(),
        },
    };

    // read: kv-conf with rapido_conf
    // FIXME: prepare RapidoConf parser(based on kv-conf)
    // kmod-parser:
    //      kmod_dir: for src_path, derived from KERNEL_INSTALL_MOD_PATH,
    //                  or default to /lib/modules/kver
    //      kver: for dst_path inside initrd

    let rapido_conf_path = "rapido.conf"; // FIXME: assuming cwd, use env::RAPIDO_CONF or RapidoConf parser

    let conf = match fs::File::open(rapido_conf_path) {
        Ok(f) => {
            let mut reader = io::BufReader::new(f);
            match kv_conf::kv_conf_process(&mut reader) {
                Ok(c) => c,
                Err(e) => {
                    println!("failed to process {}: {:?}", rapido_conf_path, e);
                    return Err(e);
                }
            }
        }
        // handle no rapido.conf
        Err(_) => HashMap::new(),
    };
    // get kver, will be replaced by lib call to get_kver later
    let kver: String = match conf.get("KERNEL_RELEASE") {
        Some(rel) => rel.clone(),
        None => {
            let proc_version = fs::read("/proc/version")?;
            let rel_slice = get_host_rel(&proc_version)?;
            rel_slice.to_string()
        }
    };
    let kver_path = format!("/lib/modules/{kver}");

    // get kmod_dir, falling back to /lib/modules/<kver>
    let kmod_dir: String = match conf.get("KERNEL_INSTALL_MOD_PATH") {
        Some(kmod) => kmod.clone(),
        None => {
            let proc_version = fs::read("/proc/version")?;
            let rel_slice = get_host_rel(&proc_version)?;
            format!("/lib/modules/{rel_slice}")
        }
    };
    //

    let cpio_out_path = match args_process(&mut state.bins.names, &mut state.kmods.names) {
        Ok(p) => p,
        Err(argument::Error::PrintHelp) => return Ok(()),
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())),
    };

    let cpio_props = cpio::ArchiveProperties{
        // Attempt 4K file data alignment within archive for Btrfs/XFS reflinks
        data_align: 4096,
        ..cpio::ArchiveProperties::default()
    };
    let mut cpio_state = cpio::ArchiveState::new(&cpio_props);

    let cpio_f = fs::OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        // for rapido we normally want to truncate any existing output file
        .truncate(true)
        .open(&cpio_out_path)?;
    let mut cpio_writer = io::BufWriter::new(cpio_f);

    // @libs_seen is an optimization to avoid resolving already-seen elf deps.
    let mut libs_seen: HashMap<String, u64> = HashMap::new();
    // avoid archiving already-archived paths
    let mut paths_seen: HashMap<PathBuf, u64> = HashMap::new();

    // process bins first, as they may add to libs *and* bins
    while let Some((bin_src, bin_dst)) = state.bins.names.get(state.bins.off) {
        let got = match path_stat(&bin_src, &BIN_PATHS) {
            Some(fse) => fse,
            None => {
                state.bins.missing.push(state.bins.off);
                state.bins.off += 1;
                continue;
            }
        };
        let amd = cpio::ArchiveMd::from(&cpio_state, &got.md)?;
        // mock up md to use for any parent directories. 0111: allow traversal
        let parent_dirs_amd = cpio::ArchiveMd{
            mode: match amd.mode & cpio::S_IFMT {
                cpio::S_IFDIR => amd.mode,
                _ => (amd.mode & !cpio::S_IFMT) | cpio::S_IFDIR | 0111,
            },
            nlink: 2,
            rmajor: 0,
            rminor: 0,
            len: 0,
            ..amd
        };
        let dst = match bin_dst {
            None => &got.path,
            Some(d) => &path::absolute(d)?,
        };

        gather_archive_dirs(
            dst.parent(),
            &parent_dirs_amd,
            &mut paths_seen,
            &mut cpio_state,
            &mut cpio_writer
        )?;
        match amd.mode & cpio::S_IFMT {
            cpio::S_IFLNK => {
                if bin_dst.is_some() {
                    eprintln!("symlink source and cpio dest paths must match");
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                let symlink_tgt = fs::read_link(&got.path)?;
                cpio::archive_symlink(&mut cpio_state, &got.path, &amd, &symlink_tgt, &mut cpio_writer)?;
                if let Ok(t) = symlink_tgt.into_os_string().into_string() {
                    // FIXME this could loop endlessly; filter dups
                    state.bins.names.push((t, None));
                } else {
                    eprintln!("bogus symlink target {:?}", &got.path);
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                println!("archived symlink: {:?}", got.path);
            },
            cpio::S_IFREG => {
                gather_archive_file(
                    &got.path,
                    &dst,
                    &amd,
                    Some(0o111),
                    &mut state.libs.names,
                    &mut libs_seen,
                    &mut cpio_state,
                    &mut cpio_writer
                )?;
                println!("archived bin: {:?}→{:?}", got.path, dst);
            },
            _ => {
                cpio::archive_path(&mut cpio_state, &dst, &amd, &mut cpio_writer)?;
                println!("archived other: {:?}→{:?}", got.path, dst);
            },
        };
        state.bins.off += 1;
    }

    // process libs next, which may add to libs
    while let Some((lib_src, lib_dst)) = state.libs.names.get(state.libs.off) {
        let got = match path_stat(&lib_src, &LIB_PATHS) {
            Some(fse) => fse,
            None => {
                state.libs.missing.push(state.libs.off);
                state.libs.off += 1;
                continue;
            }
        };
        let amd = cpio::ArchiveMd::from(&cpio_state, &got.md)?;
        // mock up md to use for any parent directories. 0111: allow traversal
        let parent_dirs_amd = cpio::ArchiveMd{
            mode: match amd.mode & cpio::S_IFMT {
                cpio::S_IFDIR => amd.mode,
                _ => (amd.mode & !cpio::S_IFMT) | cpio::S_IFDIR | 0o111,
            },
            nlink: 2,
            rmajor: 0,
            rminor: 0,
            len: 0,
            ..amd
        };
        let dst = match lib_dst {
            None => &got.path,
            Some(d) => &path::absolute(d)?,
        };
        gather_archive_dirs(
            dst.parent(),
            &parent_dirs_amd,
            &mut paths_seen,
            &mut cpio_state,
            &mut cpio_writer
        )?;
        match amd.mode & cpio::S_IFMT {
            cpio::S_IFLNK => {
                if lib_dst.is_some() {
                    eprintln!("symlink source and cpio dest paths must match");
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                let symlink_tgt = fs::read_link(&got.path)?;
                cpio::archive_symlink(&mut cpio_state, &got.path, &amd, &symlink_tgt, &mut cpio_writer)?;
                if let Ok(t) = symlink_tgt.into_os_string().into_string() {
                    // FIXME this could loop endlessly; filter dups
                    state.libs.names.push((t, None));
                } else {
                    eprintln!("bogus symlink target {:?}", &got.path);
                    return Err(io::Error::from(io::ErrorKind::InvalidInput));
                }
                println!("archived lib symlink: {:?}", got.path);
            },
            cpio::S_IFREG => {
                gather_archive_file(
                    &got.path,
                    &dst,
                    &amd,
                    None,
                    &mut state.libs.names,
                    &mut libs_seen,
                    &mut cpio_state,
                    &mut cpio_writer
                )?;
                println!("archived lib: {:?}", got.path);
            },
            _ => {
                // only support file/symlink library entries
                eprintln!(
                    "{:?}: libs gathering only supports symlinks or files, not {:o}",
                    got.path, amd.mode
                );
                state.libs.missing.push(state.libs.off);
            },
        };
        state.libs.off += 1;
    }

    // KmodContext initialization and usage
    // src: replace with kv-conf KERNEL_INSTALL_MOD_PATH value
    // dst: inside initrd it will /lib/modules/{kver}/module.path
    match KmodContext::new(Some(kmod_dir.as_str())) {
        Ok(context) => {
            let module_names: Vec<String> = state
                .kmods
                .names
                .iter()
                .map(|(name, _dst)| name.clone())
                .collect();
            let mut kmod_paths: HashSet<PathBuf> = HashSet::new();
            let kmod_root_path = Path::new(&kmod_dir);
            let kver_root_path = Path::new(&kver_path);

            for name in module_names {
                if let Some(root_mod) = context.find(&name) {
                    if root_mod.status != ModuleStatus::Builtin {
                        if root_mod.path.exists() {
                            kmod_paths.insert(root_mod.path.clone());
                        }
                        let all_deps: Vec<&String> = root_mod
                            .hard_deps
                            .iter()
                            .chain(root_mod.soft_deps_pre.iter())
                            .chain(root_mod.soft_deps_post.iter())
                            .chain(root_mod.weak_deps.iter())
                            .collect();
                        for dep_mod_name in all_deps {
                            if let Some(dep_mod) = context.find(dep_mod_name) {
                                if dep_mod.path.exists() {
                                    kmod_paths.insert(dep_mod.path.clone());
                                }
                            }
                        }
                    } else {
                        dout!("{} builtin", root_mod.name);
                    }
                } else {
                    dout!("{} Module Not Found", name);
                }
            }
            for path in kmod_paths {
                let relative_path = match path.strip_prefix(kmod_root_path) {
                    Ok(rel_path) => rel_path,
                    Err(_) => {
                        dout!("Error: Path structure mismatch.");
                        continue;
                    }
                };
                let dst_path = kver_root_path.join(relative_path);
                archive_kmod_path(&path, &dst_path, &mut cpio_state, &mut cpio_writer)?;
            }
        }
        Err(e) => {
            dout!("KmodContext Initialization Error: {}", e);
        }
    }

    let len = cpio::archive_trailer(&mut cpio_state, &mut cpio_writer)?;
    cpio_writer.flush()?;
    println!("initramfs {} written ({} bytes)", cpio_out_path.display(), len);

    Ok(())
}
