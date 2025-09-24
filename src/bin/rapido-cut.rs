// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 SUSE LLC
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs;
use std::io;
use std::io::Seek;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use elf::abi;
use elf::ElfBytes;
use elf::endian::AnyEndian;

use crosvm::argument::{self, Argument};

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
fn path_stat(name: String, paths: &[&str]) -> Option<Fsent> {
    dout!("resolving path for {:?}", name);
    let rname = std::path::Path::new(&name);
    // if name has any separator in it then we should handle it as a relative
    // or absolute path. This should be close enough as a check.
    if name.contains(std::path::MAIN_SEPARATOR_STR) {
        dout!("using relative / absolute path {:?} as-is", rname);
        return match fs::symlink_metadata(rname) {
            Ok(md) => Some(Fsent {path: rname.to_path_buf(), md: md}),
            Err(_) => None,
        }
    }

    for dir in paths.iter() {
        let p = PathBuf::from(dir).join(rname);
        let md = fs::symlink_metadata(&p);
        if md.is_ok() {
            return Some(Fsent {path: p, md: md.unwrap()});
        }
    }

    None
}

// Parse ELF NEEDED entries to gather shared object dependencies
// This function intentionally ignores any DT_RPATH paths.
// FIXME don't parse entire file - read header only
fn elf_deps(path: &PathBuf, dups_filter: &mut HashMap<String, u64>) -> Result<Vec<String>, io::Error> {
    let mut ret: Vec<String> = vec![];
    let file_data = fs::read(&path)?;
    let slice = file_data.as_slice();
    // TODO check for 4 byte ELF header first
    let file = match ElfBytes::<AnyEndian>::minimal_parse(slice) {
        Ok(f) => f,
        Err(e) => {
            // uniqe error for missing ELF header
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                    e.to_string()));
        },
    };

    let dynsyms_strs = match file.find_common_data() {
        Err(e) => {
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        },
        Ok(common) => {
            if common.dynsyms_strs.is_none() {
                dout!("no string table for {:?}", path);
                return Ok(ret);
            }
            common.dynsyms_strs.unwrap()
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

    for dyna in dynamics.iter() {
        if dyna.d_tag != abi::DT_NEEDED {
            continue;
        }
        let str_off: usize = dyna.d_val().try_into().expect("failed to get dyna offset");
        match dynsyms_strs.get(str_off) {
            Ok(sraw) => {
                let s = sraw.to_string();
                if *dups_filter.entry(s.clone()).and_modify(|s| *s += 1).or_insert(1) == 1 {
                    dout!("new elf dependency({:?}): {:?}", str_off, s);
                    ret.push(s);
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

fn args_usage(params: &[Argument]) {
    argument::print_help("rapido-cut", "OUTPUT", params);
}

fn args_process(inst: &mut Vec<String>) -> argument::Result<PathBuf> {
    let params = &[
        Argument::positional("OUTPUT", "Write initramfs archive to this file path."),
        Argument::value(
            "install",
            "FILES",
            "space separated list of files to put in initramfs with ELF dependencies.",
        ),
        Argument::short_flag('h', "help", "Print help message."),
    ];

    let mut positional_args = 0;
    let args = env::args().skip(1); // skip binary name
    let match_res = argument::set_arguments(args, params, |name, value| {
        match name {
            "" => positional_args += 1,
            "install" => {
                let inst_parsed: argument::Result<Vec<String>> = value
                    .unwrap()
                    .split(' ')
                    .map(|f| {
                        f.parse().map_err(|_| argument::Error::InvalidValue {
                            value: f.to_owned(),
                            expected: String::from("FILES must be utf-8 strings"),
                        })
                    })
                    .collect();

                inst.append(&mut inst_parsed?);
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
        // needed paths are added to the end of the gather list as they are found.
        names: Vec<String>,
        // offset that we are currently processing
        off: usize,
        // @names offset which couldn't be found
        missing: Vec<usize>,
    }

    struct State {
        bins: Gather,
        libs: Gather,
        // TODO: kmods: Gather,
        // TODO: data: Gather,  // don't check for elf deps? or just rename "bins" to "files" and
        // check exec bit?

        // located bins and libs paths with stat info
        found: Vec<Fsent>,

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
        found: vec!(),
    };


    let cpio_out_path = match args_process(&mut state.bins.names) {
        Ok(p) => p,
        Err(argument::Error::PrintHelp) => return Ok(()),
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())),
    };

    let mut cpio_props = cpio::ArchiveProperties::default();
    // for rapido we normally want to truncate any existing output file
    cpio_props.truncate_existing = true;
    // Attempt 4K file data alignment within archive for Btrfs/XFS reflinks
    cpio_props.data_align = 4096;
    let mut cpio_state = cpio::ArchiveState::new(cpio_props.initial_ino);

    let mut cpio_f = fs::OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .truncate(cpio_props.truncate_existing)
        .open(&cpio_out_path)?;
    if !cpio_props.truncate_existing {
        cpio_props.initial_data_off = cpio_f.seek(io::SeekFrom::End(0))?;
    }
    let mut cpio_writer = io::BufWriter::new(cpio_f);

    // @libs_seen is an optimization to avoid resolving already-seen elf deps.
    let mut libs_seen_filter: HashMap<String, u64> = HashMap::new();

    // process bins first, as they may add to libs *and* bins
    while let Some(this_bin) = state.bins.names.get(state.bins.off) {
        // XXX: check the current directory, or require "./" prefix?
        match path_stat(this_bin.clone(), &BIN_PATHS) {
            Some(got) => {
                if got.md.file_type().is_symlink() {
                    let symlink_tgt = fs::read_link(&got.path)?;
                    // FIXME this could loop endlessly; filter dups
                    // FIXME error
                    state.bins.names.push(symlink_tgt.into_os_string().into_string().unwrap());
                } else if got.md.mode() & 0o111 != 0 {
                    // one or more exec flags set: check for elf deps.
                    match elf_deps(&got.path, &mut libs_seen_filter) {
                        Ok(mut d) => state.libs.names.append(&mut d),
                        Err(ref e) if e.kind() == io::ErrorKind::InvalidInput => {
                            dout!("executable {:?} not an elf", this_bin);
                        },
                        Err(e) => {
                            dout!("failed to obtain dependencies for elf {:?}: {:?}", this_bin, e);
                        },
                    }
                }
                // don't check for '#!' interpreters like Dracut, it's messy

                // TODO: use got.md and open handle from elf_deps()
                cpio::archive_path(&mut cpio_state, &cpio_props, &got.path, &mut cpio_writer)?;
                println!("archived bin: {:?}", got.path);
                state.found.push(got);
            },
            None => {
                state.bins.missing.push(state.bins.off);
            },
        };
        state.bins.off += 1;
    }

    // process libs next, which may add to libs
    while let Some(this_lib) = state.libs.names.get(state.libs.off) {
        match path_stat(this_lib.clone(), &LIB_PATHS) {
            Some(got) => {
                if got.md.file_type().is_symlink() {
                    let symlink_tgt = fs::read_link(&got.path).expect("TODO no target for symlink");
                    // FIXME this could loop endlessly; filter dups
                    // FIXME error
                    state.libs.names.push(symlink_tgt.into_os_string().into_string().unwrap());
                } else {
                    // check for elf deps.
                    match elf_deps(&got.path, &mut libs_seen_filter) {
                        Ok(mut d) => state.libs.names.append(&mut d),
                        Err(ref e) if e.kind() == io::ErrorKind::InvalidInput => {
                            dout!("{:?} not an elf", this_lib);
                        },
                        Err(e) => {
                            dout!("failed to obtain dependencies for elf {:?}: {:?}", this_lib, e);
                        },
                    }
                }

                // TODO: use got.md and open handle from elf_deps()
                cpio::archive_path(&mut cpio_state, &cpio_props, &got.path, &mut cpio_writer)?;
                println!("archived lib: {:?}", got.path);
                state.found.push(got);
            },
            None => {
                state.libs.missing.push(state.libs.off);
            },
        };
        state.libs.off += 1;
    }

    cpio::archive_flush_unseen_hardlinks(&mut cpio_state, &cpio_props, &mut cpio_writer)?;
    cpio::archive_trailer(&mut cpio_writer, cpio_state.off)?;
    cpio_writer.flush()?;

    Ok(())
}
