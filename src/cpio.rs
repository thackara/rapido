// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2021 SUSE LLC

use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::Path;

macro_rules! NEWC_HDR_FMT {
    () => {
        concat!(
            "{magic}{ino:08X}{mode:08X}{uid:08X}{gid:08X}{nlink:08X}",
            "{mtime:08X}{filesize:08X}{major:08X}{minor:08X}{rmajor:08X}",
            "{rminor:08X}{namesize:08X}{chksum:08X}"
        )
    };
}

// Don't print debug messages on release builds...
#[cfg(debug_assertions)]
macro_rules! dout {
    ($($l:tt)*) => { println!($($l)*); }
}
#[cfg(not(debug_assertions))]
macro_rules! dout {
    ($($l:tt)*) => {};
}

pub const NEWC_HDR_LEN: u64 = 110;
pub const PATH_MAX: u64 = 4096;

pub struct ArchiveProperties {
    // first inode number to use. @ArchiveState.ino increments from this.
    pub initial_ino: u32,
    // if non-zero, then align file data segments to this offset by injecting
    // extra zeros after the filename string terminator.
    pub data_align: u32,
    // When injecting extra zeros into the filename field for data alignment,
    // ensure that it doesn't exceed this size. The linux kernel will ignore
    // files where namesize is larger than PATH_MAX, hence the need for this.
    pub namesize_max: u32,
    // if the archive is being appended to the end of an existing file, then
    // @initial_data_off is used when calculating @data_align alignment.
    pub initial_data_off: u64,
    // mtime, uid and gid to use for archived inodes, instead of the value
    // reported by stat.
    pub fixed_mtime: Option<u32>,
    pub fixed_uid: Option<u32>,
    pub fixed_gid: Option<u32>,
}

impl ArchiveProperties {
    pub fn default() -> ArchiveProperties {
        ArchiveProperties {
            initial_ino: 0, // match GNU cpio numbering
            data_align: 0,
            namesize_max: PATH_MAX as u32,
            initial_data_off: 0,
            fixed_mtime: None,
            fixed_uid: None,
            fixed_gid: None,
        }
    }
}

pub struct ArchiveState<'a> {
    // static properties, provided during initialization
    props: &'a ArchiveProperties,
    // offset from the start of this archive
    off: u64,
    // next mapped inode number, used instead of source file inode numbers to
    // ensure reproducibility. Inode numbers all share the same dev (major=0
    // minor=0) namespace.
    ino: u32,
}

impl ArchiveState<'_> {
    pub fn new(props: &ArchiveProperties) -> ArchiveState {
        ArchiveState {
            off: 0,
            ino: props.initial_ino,
            props,
        }
    }
}

pub fn archive_path<W: Seek + Write>(
    state: &mut ArchiveState,
    path: &Path,
    md: &fs::Metadata,
    mut writer: W,
) -> io::Result<()> {
    let mut outpath = path;
    let mut rmajor: u32 = 0;
    let mut rminor: u32 = 0;

    let ftype = md.file_type();
    if ftype.is_file() || ftype.is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "archive_path does not support files or symlinks",
        ));
    }

    outpath = match outpath.strip_prefix("./") {
        Ok(p) => {
            if p.as_os_str().as_bytes().len() == 0 {
                outpath // retain './' and '.' paths
            } else {
                p
            }
        }
        Err(_) => outpath,
    };
    let fname = outpath.as_os_str().as_bytes();
    if fname.len() + 1 >= PATH_MAX.try_into().unwrap() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }

    dout!("archiving {} with mode {:o}", outpath.display(), md.mode());

    if md.nlink() > u32::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nlink too large",
        ));
    }

    let mtime: u32 = match state.props.fixed_mtime {
        Some(t) => t,
        None => {
            // check for 2106 epoch overflow
            if md.mtime() > i64::from(u32::MAX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mtime too large for cpio",
                ));
            }
            md.mtime().try_into().unwrap()
        }
    };

    // Linux kernel uses 32-bit dev_t, encoded as mmmM MMmm. glibc uses 64-bit
    // MMMM Mmmm mmmM MMmm, which is compatible with the former.
    if ftype.is_block_device() || ftype.is_char_device() {
        let rd = md.rdev();
        rmajor = (((rd >> 32) & 0xfffff000) | ((rd >> 8) & 0x00000fff)) as u32;
        rminor = (((rd >> 12) & 0xffffff00) | (rd & 0x000000ff)) as u32;
    }

    write!(
        writer,
        NEWC_HDR_FMT!(),
        magic = "070701",
        ino = {
            let i = state.ino;
            state.ino += 1;
            i
        },
        mode = md.mode(),
        uid = match state.props.fixed_uid {
            Some(u) => u,
            None => md.uid(),
        },
        gid = match state.props.fixed_gid {
            Some(g) => g,
            None => md.gid(),
        },
        nlink = md.nlink() as u32,
        mtime = mtime,
        filesize = 0,
        major = 0,
        minor = 0,
        rmajor = rmajor,
        rminor = rminor,
        namesize = fname.len() + 1,
        chksum = 0
    )?;
    state.off += NEWC_HDR_LEN;

    writer.write_all(fname)?;
    state.off += fname.len() as u64;

    let mut seek_len: i64 = 1; // fname nulterm
    let padding_len = archive_padlen(state.off + seek_len as u64, 4);
    seek_len += padding_len as i64;
    {
        let z = vec![0u8; seek_len.try_into().unwrap()];
        writer.write_all(&z)?;
    }
    state.off += seek_len as u64;

    Ok(())
}

pub fn archive_symlink<W: Seek + Write>(
    state: &mut ArchiveState,
    path: &Path,
    md: &fs::Metadata,
    symlink_tgt: &Path,
    mut writer: W,
) -> io::Result<()> {
    let mut outpath = path;
    let tgt_bytes = symlink_tgt.as_os_str().as_bytes();
    let datalen: u32 = {
        let d: usize = tgt_bytes.len();
        if d >= PATH_MAX.try_into().unwrap() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symlink path too long",
            ));
        }
        d.try_into().unwrap()
    };
    // no zero terminator for symlink target path

    if !md.file_type().is_symlink() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    outpath = match outpath.strip_prefix("./") {
        Ok(p) => {
            if p.as_os_str().as_bytes().len() == 0 {
                outpath // retain './' and '.' paths
            } else {
                p
            }
        }
        Err(_) => outpath,
    };
    let fname = outpath.as_os_str().as_bytes();
    if fname.len() + 1 >= PATH_MAX.try_into().unwrap() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }

    dout!("archiving {} with mode {:o}", outpath.display(), md.mode());

    if md.nlink() > u32::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nlink too large",
        ));
    }

    let mtime: u32 = match state.props.fixed_mtime {
        Some(t) => t,
        None => {
            // check for 2106 epoch overflow
            if md.mtime() > i64::from(u32::MAX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mtime too large for cpio",
                ));
            }
            md.mtime().try_into().unwrap()
        }
    };

    write!(
        writer,
        NEWC_HDR_FMT!(),
        magic = "070701",
        ino = {
            let i = state.ino;
            state.ino += 1;
            i
        },
        mode = md.mode(),
        uid = match state.props.fixed_uid {
            Some(u) => u,
            None => md.uid(),
        },
        gid = match state.props.fixed_gid {
            Some(g) => g,
            None => md.gid(),
        },
        nlink = md.nlink() as u32,
        mtime = mtime,
        filesize = datalen,
        major = 0,
        minor = 0,
        rmajor = 0,
        rminor = 0,
        namesize = fname.len() + 1,
        chksum = 0
    )?;
    state.off += NEWC_HDR_LEN;

    writer.write_all(fname)?;
    state.off += fname.len() as u64;

    let mut seek_len: i64 = 1; // fname nulterm
    let padding_len = archive_padlen(state.off + seek_len as u64, 4);
    seek_len += padding_len as i64;
    {
        let z = vec![0u8; seek_len.try_into().unwrap()];
        writer.write_all(&z)?;
    }
    state.off += seek_len as u64;

    writer.write_all(tgt_bytes)?;
    state.off += u64::from(datalen);
    let dpad_len: usize = archive_padlen(state.off, 4).try_into().unwrap();
    write!(writer, "{pad:.padlen$}", padlen = dpad_len, pad = "\0\0\0")?;
    state.off += dpad_len as u64;

    Ok(())
}

pub fn archive_file<W: Seek + Write>(
    state: &mut ArchiveState,
    path: &Path,
    md: &fs::Metadata,
    in_file: &fs::File,
    mut writer: W,
) -> io::Result<()> {
    let mut outpath = path;
    let mut data_align_seek: u32 = 0;

    if !md.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file"));
    }

    outpath = match outpath.strip_prefix("./") {
        Ok(p) => {
            if p.as_os_str().as_bytes().len() == 0 {
                outpath // retain './' and '.' paths
            } else {
                p
            }
        }
        Err(_) => outpath,
    };
    let fname = outpath.as_os_str().as_bytes();
    if fname.len() + 1 >= PATH_MAX.try_into().unwrap() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }

    dout!("archiving file {} with mode {:o}", outpath.display(), md.mode());

    let mtime: u32 = match state.props.fixed_mtime {
        Some(t) => t,
        None => {
            // check for 2106 epoch overflow
            if md.mtime() > i64::from(u32::MAX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "mtime too large for cpio",
                ));
            }
            md.mtime().try_into().unwrap()
        }
    };

    let datalen: u32 = {
        if md.len() > u64::from(u32::MAX) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file too large for newc",
            ));
        }
        md.len().try_into().unwrap()
    };

    if md.nlink() > 1 {
        // For simplicity's sake, hardlinks are archived like regular files,
        // i.e. they're always assigned a unique inode number and carry a
        // corresponding data segment (if present). Use symlinks, or if you
        // really need hardlinks then create them during init.
        eprintln!(
            "{}: (nlink={}) hardlink file data may be duplicated",
            outpath.display(),
            md.nlink()
        );
    }

    if state.props.data_align > 0 && datalen > state.props.data_align {
        // XXX we're "bending" the newc spec a bit here to inject zeros
        // after fname to provide data segment alignment. These zeros are
        // accounted for in the namesize, but some applications may only
        // expect a single zero-terminator (and 4 byte alignment). GNU cpio
        // and Linux initramfs handle this fine as long as PATH_MAX isn't
        // exceeded.
        data_align_seek = {
            let len: u64 = archive_padlen(
                state.props.initial_data_off + state.off + NEWC_HDR_LEN + fname.len() as u64 + 1,
                u64::from(state.props.data_align),
            );
            let padded_namesize = len + fname.len() as u64 + 1;
            if padded_namesize > u64::from(state.props.namesize_max) {
                dout!(
                    "{} misaligned. Required padding {} exceeds namesize maximum {}.",
                    outpath.display(),
                    len,
                    state.props.namesize_max
                );
                0
            } else {
                len.try_into().unwrap()
            }
        };
    }

    write!(
        writer,
        NEWC_HDR_FMT!(),
        magic = "070701",
        ino = {
            let i = state.ino;
            state.ino += 1;
            i
        },
        mode = md.mode(),
        uid = match state.props.fixed_uid {
            Some(u) => u,
            None => md.uid(),
        },
        gid = match state.props.fixed_gid {
            Some(g) => g,
            None => md.gid(),
        },
        // see hardlink note above
        nlink = 1,
        mtime = mtime,
        filesize = datalen,
        major = 0,
        minor = 0,
        rmajor = 0,
        rminor = 0,
        namesize = fname.len() + 1 + data_align_seek as usize,
        chksum = 0
    )?;
    state.off += NEWC_HDR_LEN;

    writer.write_all(fname)?;
    state.off += fname.len() as u64;

    let mut seek_len: i64 = 1; // fname nulterm
    if data_align_seek > 0 {
        seek_len += data_align_seek as i64;
        assert_eq!(archive_padlen(state.off + seek_len as u64, 4), 0);
    } else {
        let padding_len = archive_padlen(state.off + seek_len as u64, 4);
        seek_len += padding_len as i64;
    }
    {
        let z = vec![0u8; seek_len.try_into().unwrap()];
        writer.write_all(&z)?;
    }
    state.off += seek_len as u64;

    // io::copy() can reflink: https://github.com/rust-lang/rust/pull/75272 \o/
    if datalen > 0 {
        let mut reader = io::BufReader::new(in_file);
        let copied = io::copy(&mut reader, &mut writer)?;
        if copied != u64::from(datalen) {
            dout!("copied {}, expected {}", copied, datalen);
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "copy returned unexpected length",
            ));
        }
        state.off += u64::from(datalen);
        let dpad_len: usize = archive_padlen(state.off, 4).try_into().unwrap();
        write!(writer, "{pad:.padlen$}", padlen = dpad_len, pad = "\0\0\0")?;
        state.off += dpad_len as u64;
    }

    Ok(())
}

pub fn archive_padlen(off: u64, alignment: u64) -> u64 {
    (alignment - (off & (alignment - 1))) % alignment
}

pub fn archive_trailer<W: Write>(
    state: &mut ArchiveState,
    mut writer: W
) -> io::Result<u64> {
    const FNAME: &str = "TRAILER!!!";
    const FNAME_LEN: usize = FNAME.len() + 1;

    write!(
        writer,
        NEWC_HDR_FMT!(),
        magic = "070701",
        ino = 0,
        mode = 0,
        uid = 0,
        gid = 0,
        nlink = 1,
        mtime = 0,
        filesize = 0,
        major = 0,
        minor = 0,
        rmajor = 0,
        rminor = 0,
        namesize = FNAME_LEN,
        chksum = 0
    )?;
    state.off += NEWC_HDR_LEN;

    let padding_len = archive_padlen(state.off + FNAME_LEN as u64, 4);
    write!(
        writer,
        "{}\0{pad:.padlen$}",
        FNAME,
        padlen = padding_len as usize,
        pad = "\0\0\0"
    )?;
    state.off += FNAME_LEN as u64 + padding_len as u64;

    Ok(state.off)
}
