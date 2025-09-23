// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 SUSE LLC

use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt as UnixMetadataExt;
use std::path::{Path, PathBuf};

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

struct HardlinkPath {
    infile: PathBuf,
    outfile: PathBuf,
}

struct HardlinkState {
    names: Vec<HardlinkPath>,
    source_ino: u64,
    mapped_ino: u32,
    nlink: u32,
    seen: u32,
}

struct DevState {
    dev: u64,
    hls: Vec<HardlinkState>,
}

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
    // delimiter character for the stdin file list
    pub list_separator: u8,
    // mtime, uid and gid to use for archived inodes, instead of the value
    // reported by stat.
    pub fixed_mtime: Option<u32>,
    pub fixed_uid: Option<u32>,
    pub fixed_gid: Option<u32>,
    // When archiving a subset of hardlinks, nlink values in the archive can
    // represent the subset (renumber_nlink=true) or the original source file
    // nlink values (renumber_nlink=false), where the latter matches GNU cpio.
    pub renumber_nlink: bool,
    // If OUTPUT file exists, then zero-truncate it instead of appending. The
    // default append behaviour chains archives back-to-back, i.e. multiple
    // archives will be separated by a TRAILER and 512-byte padding.
    // See Linux's Documentation/driver-api/early-userspace/buffer-format.rst
    // for details on how chained initramfs archives are handled.
    pub truncate_existing: bool,
}

impl ArchiveProperties {
    pub fn default() -> ArchiveProperties {
        ArchiveProperties {
            initial_ino: 0, // match GNU cpio numbering
            data_align: 0,
            namesize_max: PATH_MAX as u32,
            initial_data_off: 0,
            list_separator: b'\n',
            fixed_mtime: None,
            fixed_uid: None,
            fixed_gid: None,
            renumber_nlink: false,
            truncate_existing: false,
        }
    }
}

pub struct ArchiveState {
    // 2d dev + inode vector serves two purposes:
    // - dev index provides reproducible major,minor values
    // - inode@dev provides hardlink state tracking
    ids: Vec<DevState>,
    // offset from the start of this archive
    pub off: u64,
    // next mapped inode number, used instead of source file inode numbers to
    // ensure reproducability. XXX: should track inode per mapped dev?
    ino: u32,
}

impl ArchiveState {
    pub fn new(ino_start: u32) -> ArchiveState {
        ArchiveState {
            ids: Vec::new(),
            off: 0,
            ino: ino_start,
        }
    }

    // lookup or create DevState for @dev. Return @major/@minor based on index
    pub fn dev_seen(&mut self, dev: u64) -> Option<(u32, u32)> {
        let index: u64 = match self.ids.iter().position(|i| i.dev == dev) {
            Some(idx) => idx.try_into().ok()?,
            None => {
                self.ids.push(DevState {
                    dev: dev,
                    hls: Vec::new(),
                });
                (self.ids.len() - 1).try_into().ok()?
            }
        };

        let major: u32 = (index >> 32).try_into().unwrap();
        let minor: u32 = (index & u64::from(u32::MAX)).try_into().unwrap();
        Some((major, minor))
    }

    // Check whether we've already seen this hardlink's dev/inode combination.
    // If already seen, fill the existing mapped_ino.
    // Return true if this entry has been deferred (seen != nlinks)
    pub fn hardlink_seen<W: Write + Seek>(
        &mut self,
        props: &ArchiveProperties,
        mut writer: W,
        major: u32,
        minor: u32,
        md: fs::Metadata,
        inpath: &Path,
        outpath: &Path,
        mapped_ino: &mut Option<u32>,
        mapped_nlink: &mut Option<u32>,
    ) -> io::Result<bool> {
        assert!(md.nlink() > 1);
        let index = u64::from(major) << 32 | u64::from(minor);
        // reverse index->major/minor conversion that was just done
        let devstate: &mut DevState = &mut self.ids[index as usize];
        let (_index, hl) = match devstate
            .hls
            .iter_mut()
            .enumerate()
            .find(|(_, hl)| hl.source_ino == md.ino())
        {
            Some(hl) => hl,
            None => {
                devstate.hls.push(HardlinkState {
                    names: vec![HardlinkPath {
                        infile: inpath.to_path_buf(),
                        outfile: outpath.to_path_buf(),
                    }],
                    source_ino: md.ino(),
                    mapped_ino: self.ino,
                    nlink: md.nlink().try_into().unwrap(), // pre-checked
                    seen: 1,
                });
                self.ino += 1; // ino is reserved for all subsequent links
                return Ok(true);
            }
        };

        if (*hl).names.iter().any(|n| n.infile == inpath) {
            println!(
                "duplicate hardlink path {} for {}",
                inpath.display(),
                md.ino()
            );
            // GNU cpio doesn't swallow duplicates
        }

        // hl.nlink may not match md.nlink if we've come here via
        // archive_flush_unseen_hardlinks() .

        (*hl).seen += 1;
        if (*hl).seen > (*hl).nlink {
            // GNU cpio powers through if a hardlink is listed multiple times,
            // exceeding nlink.
            println!("hardlink seen {} exceeds nlink {}", (*hl).seen, (*hl).nlink);
        }

        if (*hl).seen < (*hl).nlink {
            (*hl).names.push(HardlinkPath {
                infile: inpath.to_path_buf(),
                outfile: outpath.to_path_buf(),
            });
            return Ok(true);
        }

        // a new HardlinkPath entry isn't added, as return path handles cpio
        // outpath header *and* data segment.

        for path in (*hl).names.iter().rev() {
            dout!("writing hardlink {}", path.outfile.display());
            // length already PATH_MAX validated
            let fname = path.outfile.as_os_str().as_bytes();

            write!(
                writer,
                NEWC_HDR_FMT!(),
                magic = "070701",
                ino = (*hl).mapped_ino,
                mode = md.mode(),
                uid = match props.fixed_uid {
                    Some(u) => u,
                    None => md.uid(),
                },
                gid = match props.fixed_gid {
                    Some(g) => g,
                    None => md.gid(),
                },
                nlink = match props.renumber_nlink {
                    true => (*hl).nlink,
                    false => md.nlink().try_into().unwrap(),
                },
                mtime = match props.fixed_mtime {
                    Some(t) => t,
                    None => md.mtime().try_into().unwrap(),
                },
                filesize = 0,
                major = major,
                minor = major,
                rmajor = 0,
                rminor = 0,
                namesize = fname.len() + 1,
                chksum = 0
            )?;
            self.off += NEWC_HDR_LEN;
            writer.write_all(fname)?;
            self.off += fname.len() as u64;
            // +1 as padding starts after fname nulterm
            let seeklen = 1 + archive_padlen(self.off + 1, 4);
            {
                let z = vec![0u8; seeklen.try_into().unwrap()];
                writer.write_all(&z)?;
            }
            self.off += seeklen;
        }
        *mapped_ino = Some((*hl).mapped_ino);
        // cpio nlink may be different to stat nlink if only a subset of links
        // are archived.
        if props.renumber_nlink {
            *mapped_nlink = Some((*hl).nlink);
        }

        // GNU cpio: if a name is given multiple times, exceeding nlink, then
        // subsequent names continue to be packed (with a repeat data segment),
        // using the same mapped inode.
        dout!("resetting hl at index {}", index);
        hl.seen = 0;
        hl.names.clear();

        return Ok(false);
    }
}

pub fn archive_path<W: Seek + Write>(
    state: &mut ArchiveState,
    props: &ArchiveProperties,
    path: &Path,
    mut writer: W,
) -> io::Result<()> {
    let inpath = path;
    let mut outpath = path;
    let mut datalen: u32 = 0;
    let mut rmajor: u32 = 0;
    let mut rminor: u32 = 0;
    let mut hardlink_ino: Option<u32> = None;
    let mut hardlink_nlink: Option<u32> = None;
    let mut symlink_tgt = PathBuf::new();
    let mut data_align_seek: u32 = 0;

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

    let md = match fs::symlink_metadata(inpath) {
        Ok(m) => m,
        Err(e) => {
            println!("failed to get metadata for {}: {}", inpath.display(), e);
            return Err(e);
        }
    };
    dout!("archiving {} with mode {:o}", outpath.display(), md.mode());

    let (major, minor) = match state.dev_seen(md.dev()) {
        Some((maj, min)) => (maj, min),
        None => return Err(io::Error::new(io::ErrorKind::Other, "failed to map dev")),
    };

    if md.nlink() > u32::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nlink too large",
        ));
    }

    let mtime: u32 = match props.fixed_mtime {
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

    let ftype = md.file_type();
    if ftype.is_symlink() {
        symlink_tgt = fs::read_link(inpath)?;
        datalen = {
            let d: usize = symlink_tgt.as_os_str().as_bytes().len();
            if d >= PATH_MAX.try_into().unwrap() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "symlink path too long",
                ));
            }
            d.try_into().unwrap()
        };
        // no zero terminator for symlink target path
    }

    // Linux kernel uses 32-bit dev_t, encoded as mmmM MMmm. glibc uses 64-bit
    // MMMM Mmmm mmmM MMmm, which is compatible with the former.
    if ftype.is_block_device() || ftype.is_char_device() {
        let rd = md.rdev();
        rmajor = (((rd >> 32) & 0xfffff000) | ((rd >> 8) & 0x00000fff)) as u32;
        rminor = (((rd >> 12) & 0xffffff00) | (rd & 0x000000ff)) as u32;
    }

    if ftype.is_file() {
        datalen = {
            if md.len() > u64::from(u32::MAX) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file too large for newc",
                ));
            }
            md.len().try_into().unwrap()
        };

        if md.nlink() > 1 {
            // follow GNU cpio's behaviour of attaching hardlink data only to
            // the last entry in the archive.
            let deferred = state.hardlink_seen(
                &props,
                &mut writer,
                major,
                minor,
                md.clone(),
                &inpath,
                outpath,
                &mut hardlink_ino,
                &mut hardlink_nlink,
            )?;
            if deferred {
                dout!("deferring hardlink {} data portion", outpath.display());
                return Ok(());
            }
        }

        if props.data_align > 0 && datalen > props.data_align {
            // XXX we're "bending" the newc spec a bit here to inject zeros
            // after fname to provide data segment alignment. These zeros are
            // accounted for in the namesize, but some applications may only
            // expect a single zero-terminator (and 4 byte alignment). GNU cpio
            // and Linux initramfs handle this fine as long as PATH_MAX isn't
            // exceeded.
            data_align_seek = {
                let len: u64 = archive_padlen(
                    props.initial_data_off + state.off + NEWC_HDR_LEN + fname.len() as u64 + 1,
                    u64::from(props.data_align),
                );
                let padded_namesize = len + fname.len() as u64 + 1;
                if padded_namesize > u64::from(props.namesize_max) {
                    dout!(
                        "{} misaligned. Required padding {} exceeds namesize maximum {}.",
                        outpath.display(),
                        len,
                        props.namesize_max
                    );
                    0
                } else {
                    len.try_into().unwrap()
                }
            };
        }
    }

    write!(
        writer,
        NEWC_HDR_FMT!(),
        magic = "070701",
        ino = match hardlink_ino {
            Some(i) => i,
            None => {
                let i = state.ino;
                state.ino += 1;
                i
            }
        },
        mode = md.mode(),
        uid = match props.fixed_uid {
            Some(u) => u,
            None => md.uid(),
        },
        gid = match props.fixed_gid {
            Some(g) => g,
            None => md.gid(),
        },
        nlink = match hardlink_nlink {
            Some(n) => n,
            None => md.nlink().try_into().unwrap(),
        },
        mtime = mtime,
        filesize = datalen,
        major = major,
        minor = major,
        rmajor = rmajor,
        rminor = rminor,
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
        if ftype.is_file() {
            let mut reader = io::BufReader::new(fs::File::open(inpath)?);
            let copied = io::copy(&mut reader, &mut writer)?;
            if copied != u64::from(datalen) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "copy returned unexpected length",
                ));
            }
        } else if ftype.is_symlink() {
            writer.write_all(symlink_tgt.as_os_str().as_bytes())?;
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

// this fn is inefficient, but optimizing for hardlinks isn't high priority
pub fn archive_flush_unseen_hardlinks<W: Write + Seek>(
    state: &mut ArchiveState,
    props: &ArchiveProperties,
    mut writer: W,
) -> io::Result<()> {
    let mut deferred_inpaths: Vec<PathBuf> = Vec::new();
    for id in state.ids.iter_mut() {
        for hl in id.hls.iter_mut() {
            if hl.seen == 0 || hl.seen == hl.nlink {
                dout!("HardlinkState complete with seen {}", hl.seen);
                continue;
            }
            dout!(
                "pending HardlinkState with seen {} != nlinks {}",
                hl.seen,
                hl.nlink
            );

            while hl.names.len() > 0 {
                let path = hl.names.pop().unwrap();
                deferred_inpaths.push(path.infile);
            }
            // ensure that data segment gets added on archive_path recall
            hl.nlink = hl.seen;
            hl.seen = 0;
            // existing allocated inode should be used
        }
    }

    if deferred_inpaths.len() > 0 {
        // rotate-right to match gnu ordering
        deferred_inpaths.rotate_right(1);

        // .reverse() to match gnu ordering
        for p in deferred_inpaths.iter().rev() {
            archive_path(state, props, p.as_path(), &mut writer)?;
        }
    }

    Ok(())
}

pub fn archive_trailer<W: Write>(mut writer: W, cur_off: u64) -> io::Result<u64> {
    let fname = "TRAILER!!!";
    let fname_len = fname.len() + 1;

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
        namesize = fname_len,
        chksum = 0
    )?;
    let mut off: u64 = cur_off + NEWC_HDR_LEN;

    let padding_len = archive_padlen(off + fname_len as u64, 4);
    write!(
        writer,
        "{}\0{pad:.padlen$}",
        fname,
        padlen = padding_len as usize,
        pad = "\0\0\0"
    )?;
    off += fname_len as u64 + padding_len as u64;

    Ok(off)
}
