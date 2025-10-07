// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 SUSE LLC
use std::convert::TryInto;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crosvm::argument::{self, Argument};

fn archive_loop<R: BufRead, W: Seek + Write>(
    mut reader: R,
    mut writer: W,
    props: &cpio::ArchiveProperties,
) -> io::Result<u64> {
    if props.data_align > 0 && (props.initial_data_off + u64::from(props.data_align)) % 4 != 0 {
        // must satisfy both data_align and cpio 4-byte padding alignment
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "data alignment must be a multiple of 4",
        ));
    }

    let mut state = cpio::ArchiveState::new(props.initial_ino);
    loop {
        let mut linebuf: Vec<u8> = Vec::new();
        let mut r = reader.by_ref().take(cpio::PATH_MAX);
        match r.read_until(props.list_separator, &mut linebuf) {
            Ok(l) => {
                if l == 0 {
                    break; // EOF
                }
                if l >= cpio::PATH_MAX.try_into().unwrap() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
                }
            }
            Err(e) => {
                println!("read_until() failed: {}", e);
                return Err(e);
            }
        };

        // trim separator. len > 0 already checked.
        let last_byte = linebuf.last().unwrap();
        if *last_byte == props.list_separator {
            linebuf.pop().unwrap();
            if linebuf.len() == 0 {
                continue;
            }
        } else {
            println!(
                "\'{:0x}\' ending not separator \'{:0x}\' terminated",
                last_byte, props.list_separator
            );
        }

        let linestr = OsStr::from_bytes(linebuf.as_slice());
        let path = Path::new(linestr);
        let md = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                println!("failed to get metadata for {}: {}", path.display(), e);
                return Err(e);
            }
        };
        cpio::archive_path(&mut state, props, path, &md, &mut writer)?;
    }
    cpio::archive_flush_unseen_hardlinks(&mut state, props, &mut writer)?;
    state.off = cpio::archive_trailer(&mut writer, state.off)?;

    // GNU cpio pads the end of an archive out to blocklen with zeros
    let block_padlen = cpio::archive_padlen(state.off, 512);
    if block_padlen > 0 {
        let z = vec![0u8; block_padlen.try_into().unwrap()];
        writer.write_all(&z)?;
        state.off += block_padlen;
    }
    writer.flush()?;

    Ok(state.off)
}

fn params_usage(params: &[Argument]) {
    argument::print_help("dracut-cpio", "OUTPUT", params);
    println!("\nExample: find fs-tree/ | dracut-cpio archive.cpio\n");
}

fn params_process(props: &mut cpio::ArchiveProperties) -> argument::Result<PathBuf> {
    let params = &[
        Argument::positional("OUTPUT", "Write cpio archive to this file path."),
        Argument::value(
            "data-align",
            "ALIGNMENT",
            "Attempt to pad archive to achieve ALIGNMENT for file data.",
        ),
        Argument::short_flag(
            '0',
            "null",
            "Expect null delimeters in stdin filename list instead of newline.",
        ),
        Argument::value(
            "mtime",
            "EPOCH",
            "Use EPOCH for archived mtime instead of filesystem reported values.",
        ),
        Argument::value(
            "owner",
            "UID:GID",
            "Use UID and GID instead of filesystem reported owner values.",
        ),
        Argument::flag(
            "truncate-existing",
            "Truncate and overwrite any existing OUTPUT file, instead of appending.",
        ),
        Argument::short_flag('h', "help", "Print help message."),
    ];

    let mut positional_args = 0;
    let args = env::args().skip(1); // skip binary name
    let match_res = argument::set_arguments(args, params, |name, value| {
        match name {
            "" => positional_args += 1,
            "data-align" => {
                let v: u32 = value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("data-align must be an integer"),
                    })?;
                if v > props.namesize_max {
                    println!(
                        concat!(
                            "Requested data-align {} larger than namesize maximum {}.",
                            " This will likely result in misalignment."
                        ),
                        v, props.namesize_max
                    );
                }
                props.data_align = v;
            }
            "null" => props.list_separator = b'\0',
            "mtime" => {
                let v: u32 = value
                    .unwrap()
                    .parse()
                    .map_err(|_| argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("mtime must be an integer"),
                    })?;
                props.fixed_mtime = Some(v);
            }
            "owner" => {
                let ugv_parsed: argument::Result<Vec<u32>> = value
                    .unwrap()
                    .split(':')
                    .map(|id| {
                        id.parse().map_err(|_| argument::Error::InvalidValue {
                            value: id.to_owned(),
                            expected: String::from("uid/gid must be an integer"),
                        })
                    })
                    .collect();

                let ugv_parsed = ugv_parsed?;
                if ugv_parsed.len() != 2 {
                    return Err(argument::Error::InvalidValue {
                        value: value.unwrap().to_owned(),
                        expected: String::from("owner must be UID:GID"),
                    });
                }
                props.fixed_uid = Some(ugv_parsed[0]);
                props.fixed_gid = Some(ugv_parsed[1]);
            }
            "truncate-existing" => props.truncate_existing = true,
            "help" => return Err(argument::Error::PrintHelp),
            _ => unreachable!(),
        };
        Ok(())
    });

    match match_res {
        Ok(_) => {
            if positional_args != 1 {
                params_usage(params);
                return Err(argument::Error::ExpectedArgument(
                    "one OUTPUT parameter required".to_string(),
                ));
            }
        }
        Err(e) => {
            params_usage(params);
            return Err(e);
        }
    }

    let last_arg = env::args_os().last().unwrap();
    Ok(PathBuf::from(&last_arg))
}

fn main() -> io::Result<()> {
    let mut props = cpio::ArchiveProperties::default();
    let output_path = match params_process(&mut props) {
        Ok(p) => p,
        Err(argument::Error::PrintHelp) => return Ok(()),
        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidInput, e.to_string())),
    };

    let mut f = fs::OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .truncate(props.truncate_existing)
        .open(&output_path)?;
    if !props.truncate_existing {
        props.initial_data_off = f.seek(io::SeekFrom::End(0))?;
    }
    let mut writer = io::BufWriter::new(f);

    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin);

    let _wrote = archive_loop(&mut reader, &mut writer, &props)?;

    if props.initial_data_off > 0 {
        println!(
            "appended {} bytes to archive {} at offset {}",
            _wrote,
            output_path.display(),
            props.initial_data_off
        );
    } else {
        println!(
            "wrote {} bytes to archive {}",
            _wrote,
            output_path.display()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp;
    use std::os::unix::fs as unixfs;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    struct TempWorkDir {
        prev_dir: PathBuf,
        parent_tmp_dir: PathBuf,
        cleanup_files: Vec<PathBuf>,
        cleanup_dirs: Vec<PathBuf>,
        ignore_cleanup: bool, // useful for debugging
    }

    impl TempWorkDir {
        // create a temporary directory under CWD and cd into it.
        // The directory will be cleaned up when twd goes out of scope.
        pub fn new() -> TempWorkDir {
            let mut buf = [0u8; 16];
            let mut s = String::from("cpio-selftest-");
            fs::File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut buf)
                .unwrap();
            for i in &buf {
                s.push_str(&format!("{:02x}", i).to_string());
            }
            let mut twd = TempWorkDir {
                prev_dir: env::current_dir().unwrap(),
                parent_tmp_dir: {
                    let mut t = env::current_dir().unwrap().clone();
                    t.push(s);
                    println!("parent_tmp_dir: {}", t.display());
                    t
                },
                cleanup_files: Vec::new(),
                cleanup_dirs: Vec::new(),
                ignore_cleanup: false,
            };
            fs::create_dir(&twd.parent_tmp_dir).unwrap();
            twd.cleanup_dirs.push(twd.parent_tmp_dir.clone());
            env::set_current_dir(&twd.parent_tmp_dir).unwrap();

            twd
        }

        pub fn create_tmp_file(&mut self, name: &str, len_bytes: u64) {
            let mut bytes = len_bytes;
            let f = fs::File::create(name).unwrap();
            self.cleanup_files.push(PathBuf::from(name));
            let mut writer = io::BufWriter::new(f);
            let mut buf = [0u8; 512];

            for (i, elem) in buf.iter_mut().enumerate() {
                *elem = !(i & 0xFF) as u8;
            }

            while bytes > 0 {
                let this_len = cmp::min(buf.len(), bytes.try_into().unwrap());
                writer.write_all(&buf[0..this_len]).unwrap();
                bytes -= this_len as u64;
            }

            writer.flush().unwrap();
        }

        pub fn create_tmp_dir(&mut self, name: &str) {
            fs::create_dir(name).unwrap();
            self.cleanup_dirs.push(PathBuf::from(name));
        }

        // execute coreutils mknod NAME TYPE [MAJOR MINOR]
        pub fn create_tmp_mknod(&mut self, name: &str, typ: char,
                                maj_min: Option<(u32, u32)>) {
            let t = typ.to_string();
            let proc = match maj_min {
                Some(maj_min) => {
                    let (maj, min) = maj_min;
                    Command::new("mknod")
                        .args(&[name, &t, &maj.to_string(), &min.to_string()])
                        .spawn()
                },
                None => Command::new("mknod").args(&[name, &t]).spawn()
            };
            let status = proc.expect("mknod failed to start").wait().unwrap();
            assert!(status.success());

            self.cleanup_files.push(PathBuf::from(name));
        }
    }

    impl Drop for TempWorkDir {
        fn drop(&mut self) {
            for f in self.cleanup_files.iter().rev() {
                if self.ignore_cleanup {
                    println!("ignoring cleanup of file {}", f.display());
                    continue;
                }
                println!("cleaning up test file at {}", f.display());
                match fs::remove_file(f) {
                    Err(e) => println!("file removal failed {}", e),
                    Ok(_) => {}
                };
            }
            for f in self.cleanup_dirs.iter().rev() {
                if self.ignore_cleanup {
                    println!("ignoring cleanup of dir {}", f.display());
                    continue;
                }
                println!("cleaning up test dir at {}", f.display());
                match fs::remove_dir(f) {
                    Err(e) => println!("dir removal failed {}", e),
                    Ok(_) => {}
                };
            }
            println!("returning cwd to {}", self.prev_dir.display());
            env::set_current_dir(self.prev_dir.as_path()).unwrap();
        }
    }

    fn gnu_cpio_create(stdinput: &[u8], out: &str) {
        let mut proc = Command::new("cpio")
            // As of GNU cpio commit 6a94d5e ("New option --ignore-dirnlink"),
            // the --reproducible option hardcodes archived directory nlink
            // values as 2. Omit it and use the dir.st_nlink value.
            .args(&[
                "--quiet",
                "-o",
                "-H",
                "newc",
                "--ignore-devno",
                "--renumber-inodes",
                "-F",
                out,
            ])
            .stdin(Stdio::piped())
            .spawn()
            .expect("GNU cpio failed to start");
        {
            let mut stdin = proc.stdin.take().unwrap();
            stdin.write_all(stdinput).expect("Failed to write to stdin");
        }

        let status = proc.wait().unwrap();
        assert!(status.success());
    }

    fn test_archive_empty_file() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 0);

        gnu_cpio_create("file.txt\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        // use dracut-cpio to archive file.txt
        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("file.txt\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_small_file() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 33);

        gnu_cpio_create("file.txt\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("file.txt\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 2 + 33);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_prefixed_path() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 0);

        gnu_cpio_create("./file.txt\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("./file.txt\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_absolute_path() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 0);

        let canon_path = fs::canonicalize("file.txt").unwrap();
        let mut canon_file_list = canon_path.into_os_string();
        canon_file_list.push("\n");

        gnu_cpio_create(canon_file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(canon_file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_dir() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_dir("dir");

        gnu_cpio_create("dir\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("dir\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_dir_file() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_dir("dir");
        twd.create_tmp_file("dir/file.txt", 512 * 32);
        let file_list: &str = "dir\n\ndir/file.txt\n"; // double separator

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 512 * 32);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_dot_path() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_dir("dir");
        twd.create_tmp_file("dir/file.txt", 512 * 32);
        let file_list: &str = ".\ndir\ndir/file.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 4 + 512 * 32);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_dot_slash_path() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_dir("dir");
        twd.create_tmp_file("dir/file.txt", 512 * 32);
        let file_list: &str = "./\ndir\ndir/file.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 4 + 512 * 32);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_symlink() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 0);
        unixfs::symlink("file.txt", "symlink.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("symlink.txt"));

        gnu_cpio_create("file.txt\nsymlink.txt\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("file.txt\nsymlink.txt\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_fifo() {
        let mut twd = TempWorkDir::new();

        twd.create_tmp_mknod("fifo", 'p', None);

        gnu_cpio_create("fifo\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("fifo\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_char() {
        let mut twd = TempWorkDir::new();

        gnu_cpio_create("/dev/zero\n".as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("/dev/zero\n".as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert_eq!(wrote, 512);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_data_align() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_dir("dir");
        twd.create_tmp_file("dir/file.txt", 1024 * 1024); // 1M

        twd.create_tmp_dir("extractor");
        let f = fs::File::create("extractor/dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new("dir\ndir/file.txt\n".as_bytes());
        // 4k cpio data segment alignment injects zeros after filename nullterm
        let wrote = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties {
                data_align: 4096,
                ..cpio::ArchiveProperties::default()
            },
        )
        .unwrap();
        twd.cleanup_files
            .push(PathBuf::from("extractor/dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 1024 * 1024);

        // check 4k data segment alignment
        let mut proc = Command::new("diff")
            .args(&["dir/file.txt", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .expect("diff failed to start");
        {
            let f = fs::File::open("extractor/dracut.cpio").unwrap();
            let mut reader = io::BufReader::new(f);
            reader.seek(io::SeekFrom::Start(4096)).unwrap();
            let mut take = reader.take(1024 * 1024 as u64);
            let mut stdin = proc.stdin.take().unwrap();
            let copied = io::copy(&mut take, &mut stdin).unwrap();
            assert_eq!(copied, 1024 * 1024);
        }
        let status = proc.wait().unwrap();
        assert!(status.success());

        // confirm that GNU cpio can extract fname-zeroed paths
        let status = Command::new("cpio")
            .current_dir("extractor")
            .args(&["--quiet", "-i", "-H", "newc", "-F", "dracut.cpio"])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        twd.cleanup_files
            .push(PathBuf::from("extractor/dir/file.txt"));
        twd.cleanup_dirs.push(PathBuf::from("extractor/dir"));

        let status = Command::new("diff")
            .args(&["dir/file.txt", "extractor/dir/file.txt"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_data_align_off() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_dir("dir1");
        twd.create_tmp_dir("dir2");
        twd.create_tmp_dir("dir3");
        twd.create_tmp_file("dir1/file.txt", 514 * 1024);

        twd.create_tmp_dir("extractor");
        let data_before_cpio = [5u8; 16384 + 4];
        let f = fs::File::create("extractor/dracut.cpio").unwrap();
        twd.cleanup_files
            .push(PathBuf::from("extractor/dracut.cpio"));
        let mut writer = io::BufWriter::new(f);
        writer.write_all(&data_before_cpio).unwrap();
        let mut reader = io::BufReader::new("dir1\ndir2\ndir3\ndir1/file.txt\n".as_bytes());
        let wrote = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties {
                data_align: 4096,
                initial_data_off: data_before_cpio.len() as u64,
                ..cpio::ArchiveProperties::default()
            },
        )
        .unwrap();
        assert!(wrote > cpio::NEWC_HDR_LEN * 5 + 514 * 1024);

        let mut proc = Command::new("diff")
            .args(&["dir1/file.txt", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .expect("diff failed to start");
        {
            let f = fs::File::open("extractor/dracut.cpio").unwrap();
            let mut reader = io::BufReader::new(f);
            reader.seek(io::SeekFrom::Start(16384 + 4096)).unwrap();
            let mut take = reader.take(514 * 1024 as u64);
            let mut stdin = proc.stdin.take().unwrap();
            let copied = io::copy(&mut take, &mut stdin).unwrap();
            assert_eq!(copied, 514 * 1024);
        }
        let status = proc.wait().unwrap();
        assert!(status.success());
    }

    fn test_archive_data_align_off_bad() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 514 * 1024);

        let data_before_cpio = [5u8; 16384 + 3];
        let f = fs::File::create("dracut.cpio").unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        let mut writer = io::BufWriter::new(f);
        writer.write_all(&data_before_cpio).unwrap();
        let mut reader = io::BufReader::new("file.txt\n".as_bytes());
        let res = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties {
                data_align: 4096,
                initial_data_off: data_before_cpio.len() as u64,
                ..cpio::ArchiveProperties::default()
            },
        );
        assert!(res.is_err());
        assert_eq!(io::ErrorKind::InvalidInput, res.unwrap_err().kind());
    }

    fn test_archive_hardlinks_order() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 512 * 4);
        fs::hard_link("file.txt", "link1.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link1.txt"));
        fs::hard_link("file.txt", "link2.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link2.txt"));
        twd.create_tmp_file("another.txt", 512 * 4);
        let file_list: &str = "file.txt\nanother.txt\nlink1.txt\nlink2.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 5 + 512 * 8);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_hardlinks_empty() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 0);
        fs::hard_link("file.txt", "link1.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link1.txt"));
        fs::hard_link("file.txt", "link2.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link2.txt"));
        twd.create_tmp_file("another.txt", 512 * 4);
        let file_list: &str = "file.txt\nanother.txt\nlink1.txt\nlink2.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 5 + 512 * 4);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_hardlinks_missing() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 512 * 4);
        fs::hard_link("file.txt", "link1.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link1.txt"));
        fs::hard_link("file.txt", "link2.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link2.txt"));
        fs::hard_link("file.txt", "link3.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link3.txt"));
        twd.create_tmp_file("another.txt", 512 * 4);
        // link2 missing from the archive, throwing off deferrals
        let file_list: &str = "file.txt\nanother.txt\nlink1.txt\nlink3.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 5 + 512 * 8);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_hardlinks_multi() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 512 * 4);
        fs::hard_link("file.txt", "link1.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link1.txt"));
        fs::hard_link("file.txt", "link2.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("link2.txt"));
        twd.create_tmp_file("another.txt", 512 * 4);
        fs::hard_link("another.txt", "anotherlink.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("anotherlink.txt"));
        // link2 missing from the archive, throwing off deferrals
        let file_list: &str = "file.txt\nanother.txt\nlink1.txt\nanotherlink.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 5 + 512 * 8);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_duplicates() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 512 * 4);
        twd.create_tmp_file("another.txt", 512 * 4);
        // file.txt is listed twice
        let file_list: &str = "file.txt\nanother.txt\nfile.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 4 + 512 * 12);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_hardlink_duplicates() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file.txt", 512 * 4);
        fs::hard_link("file.txt", "ln1.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("ln1.txt"));
        fs::hard_link("file.txt", "ln2.txt").unwrap();
        twd.cleanup_files.push(PathBuf::from("ln2.txt"));
        twd.create_tmp_file("f2.txt", 512 * 4);
        // ln1 listed twice
        let file_list: &str = "file.txt\nf2.txt\nln1.txt\nln1.txt\nln1.txt\n";

        gnu_cpio_create(file_list.as_bytes(), "gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 4 + 512 * 8);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_list_separator() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file1", 33);
        twd.create_tmp_file("file2", 55);
        let file_list_nulldelim: &str = "file1\0file2\0";

        let mut proc = Command::new("cpio")
            .args(&[
                "--quiet",
                "-o",
                "-H",
                "newc",
                "--ignore-devno",
                "--renumber-inodes",
                "-F",
                "gnu.cpio",
                "--null",
            ])
            .stdin(Stdio::piped())
            .spawn()
            .expect("GNU cpio failed to start");
        {
            let mut stdin = proc.stdin.take().unwrap();
            stdin
                .write_all(file_list_nulldelim.as_bytes())
                .expect("Failed to write to stdin");
        }

        let status = proc.wait().unwrap();
        assert!(status.success());
        twd.cleanup_files.push(PathBuf::from("gnu.cpio"));

        let f = fs::File::create("dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list_nulldelim.as_bytes());
        let wrote = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties {
                list_separator: b'\0',
                ..cpio::ArchiveProperties::default()
            },
        )
        .unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 33 + 55);

        let status = Command::new("diff")
            .args(&["gnu.cpio", "dracut.cpio"])
            .status()
            .expect("diff failed to start");
        assert!(status.success());
    }

    fn test_archive_fixed_mtime() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file1", 33);
        twd.create_tmp_file("file2", 55);
        let file_list: &str = "file1\nfile2\n";

        twd.create_tmp_dir("extractor");
        let f = fs::File::create("extractor/dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties {
                fixed_mtime: Some(0),
                ..cpio::ArchiveProperties::default()
            },
        )
        .unwrap();
        twd.cleanup_files
            .push(PathBuf::from("extractor/dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 33 + 55);

        let status = Command::new("cpio")
            .current_dir("extractor")
            .args(&[
                "--quiet",
                "-i",
                "--preserve-modification-time",
                "-H",
                "newc",
                "-F",
                "dracut.cpio",
            ])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        twd.cleanup_files.push(PathBuf::from("extractor/file1"));
        twd.cleanup_files.push(PathBuf::from("extractor/file2"));

        let md = fs::symlink_metadata("extractor/file1").unwrap();
        assert_eq!(md.mtime(), 0);
        let md = fs::symlink_metadata("extractor/file2").unwrap();
        assert_eq!(md.mtime(), 0);
    }

    fn test_archive_stat_mtime() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file1", 33);
        twd.create_tmp_file("file2", 55);
        let file_list: &str = "file1\nfile2\n";

        twd.create_tmp_dir("extractor");
        let f = fs::File::create("extractor/dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        assert_eq!(cpio::ArchiveProperties::default().fixed_mtime, None);
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files
            .push(PathBuf::from("extractor/dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 33 + 55);

        let status = Command::new("cpio")
            .current_dir("extractor")
            .args(&[
                "--quiet",
                "-i",
                "--preserve-modification-time",
                "-H",
                "newc",
                "-F",
                "dracut.cpio",
            ])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        twd.cleanup_files.push(PathBuf::from("extractor/file1"));
        twd.cleanup_files.push(PathBuf::from("extractor/file2"));

        let src_md = fs::symlink_metadata("file1").unwrap();
        let ex_md = fs::symlink_metadata("extractor/file1").unwrap();
        assert_eq!(src_md.mtime(), ex_md.mtime());
        let src_md = fs::symlink_metadata("file2").unwrap();
        let ex_md = fs::symlink_metadata("extractor/file2").unwrap();
        assert_eq!(src_md.mtime(), ex_md.mtime());
    }

    fn test_archive_fixed_owner() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file1", 33);
        twd.create_tmp_file("file2", 55);
        let file_list: &str = "file1\nfile2\n";

        let md = fs::symlink_metadata("file1").unwrap();
        // ideally we should check the process euid, but this will do...
        if md.uid() != 0 {
            println!("SKIPPED: this test requires root");
            return;
        }

        twd.create_tmp_dir("extractor");
        let f = fs::File::create("extractor/dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties {
                fixed_uid: Some(65534),
                fixed_gid: Some(65534),
                ..cpio::ArchiveProperties::default()
            },
        )
        .unwrap();
        twd.cleanup_files
            .push(PathBuf::from("extractor/dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 33 + 55);

        let status = Command::new("cpio")
            .current_dir("extractor")
            .args(&["--quiet", "-i", "-H", "newc", "-F", "dracut.cpio"])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        twd.cleanup_files.push(PathBuf::from("extractor/file1"));
        twd.cleanup_files.push(PathBuf::from("extractor/file2"));

        let md = fs::symlink_metadata("extractor/file1").unwrap();
        assert_eq!(md.uid(), 65534);
        assert_eq!(md.gid(), 65534);
        let md = fs::symlink_metadata("extractor/file2").unwrap();
        assert_eq!(md.uid(), 65534);
        assert_eq!(md.gid(), 65534);
    }

    fn test_archive_stat_owner() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file1", 33);
        twd.create_tmp_file("file2", 55);
        let file_list: &str = "file1\nfile2\n";

        twd.create_tmp_dir("extractor");
        let f = fs::File::create("extractor/dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        assert_eq!(cpio::ArchiveProperties::default().fixed_uid, None);
        assert_eq!(cpio::ArchiveProperties::default().fixed_gid, None);
        let wrote = archive_loop(&mut reader, &mut writer, &cpio::ArchiveProperties::default()).unwrap();
        twd.cleanup_files
            .push(PathBuf::from("extractor/dracut.cpio"));
        assert!(wrote > cpio::NEWC_HDR_LEN * 3 + 33 + 55);

        let status = Command::new("cpio")
            .current_dir("extractor")
            .args(&["--quiet", "-i", "-H", "newc", "-F", "dracut.cpio"])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        twd.cleanup_files.push(PathBuf::from("extractor/file1"));
        twd.cleanup_files.push(PathBuf::from("extractor/file2"));

        let src_md = fs::symlink_metadata("file1").unwrap();
        let ex_md = fs::symlink_metadata("extractor/file1").unwrap();
        assert_eq!(src_md.uid(), ex_md.uid());
        assert_eq!(src_md.gid(), ex_md.gid());
        let src_md = fs::symlink_metadata("file2").unwrap();
        let ex_md = fs::symlink_metadata("extractor/file2").unwrap();
        assert_eq!(src_md.uid(), ex_md.uid());
        assert_eq!(src_md.gid(), ex_md.gid());
    }

    fn test_archive_dev_maj_min() {
        let mut twd = TempWorkDir::new();
        twd.create_tmp_file("file1", 0);

        let md = fs::symlink_metadata("file1").unwrap();
        if md.uid() != 0 {
            println!("SKIPPED: this test requires root");
            return;
        }

        twd.create_tmp_mknod("bdev1", 'b', Some((0x01, 0x01)));
        twd.create_tmp_mknod("bdev2", 'b', Some((0x02, 0x100)));
        twd.create_tmp_mknod("bdev3", 'b', Some((0x03, 0x1000)));
        twd.create_tmp_mknod("bdev4", 'b', Some((0x04, 0x10000)));
        twd.create_tmp_mknod("bdev5", 'b', Some((0x100, 0x05)));
        twd.create_tmp_mknod("bdev6", 'b', Some((0x100, 0x06)));
        let file_list: &str = "file1\nbdev1\nbdev2\nbdev3\nbdev4\nbdev5\nbdev6\n";

        // create GNU cpio archive
        twd.create_tmp_dir("gnucpio_xtr");
        gnu_cpio_create(file_list.as_bytes(), "gnucpio_xtr/gnu.cpio");
        twd.cleanup_files.push(PathBuf::from("gnucpio_xtr/gnu.cpio"));

        // create Dracut cpio archive
        twd.create_tmp_dir("dracut_xtr");
        let f = fs::File::create("dracut_xtr/dracut.cpio").unwrap();
        let mut writer = io::BufWriter::new(f);
        let mut reader = io::BufReader::new(file_list.as_bytes());
        let wrote = archive_loop(
            &mut reader,
            &mut writer,
            &cpio::ArchiveProperties::default()
        )
        .unwrap();
        twd.cleanup_files.push(PathBuf::from("dracut_xtr/dracut.cpio"));

        let file_list_count = file_list.split_terminator('\n').count() as u64;
        assert!(wrote >= cpio::NEWC_HDR_LEN * file_list_count
                         + (file_list.len() as u64));

        let status = Command::new("cpio")
            .current_dir("gnucpio_xtr")
            .args(&["--quiet", "-i", "-H", "newc", "-F", "gnu.cpio"])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        for s in file_list.split_terminator('\n') {
            let p = PathBuf::from("gnucpio_xtr/".to_owned() + s);
            twd.cleanup_files.push(p);
        }

        let status = Command::new("cpio")
            .current_dir("dracut_xtr")
            .args(&["--quiet", "-i", "-H", "newc", "-F", "dracut.cpio"])
            .status()
            .expect("GNU cpio failed to start");
        assert!(status.success());
        for s in file_list.split_terminator('\n') {
            let dp = PathBuf::from("dracut_xtr/".to_owned() + s);
            twd.cleanup_files.push(dp);
        }

        // diff extracted major/minor between dracut and GNU cpio created archives
        for s in file_list.split_terminator('\n') {
            let gmd = fs::symlink_metadata("gnucpio_xtr/".to_owned() + s).unwrap();
            let dmd = fs::symlink_metadata("dracut_xtr/".to_owned() + s).unwrap();
            print!("{}: cpio extracted dev_t gnu: {:#x}, dracut: {:#x}\n",
                   s, gmd.rdev(), dmd.rdev());
            assert!(gmd.rdev() == dmd.rdev());
        }
    }

    #[test]
    fn test_archive_all_single_threaded() {
        // Each test_archive_ function changes its CWD and cargo test spawns
        // multiple threads for concurrent testing by default, unless given
        // --test-threads=1. Therefore, use a single wrapper test so that people
        // don't get confused by multi-threaded "cargo test" failures.
        // If someone finds a way make single-threaded the default for
        // "cargo test" then we can drop this wrapper in future.
        test_archive_empty_file();
        test_archive_small_file();
        test_archive_prefixed_path();
        test_archive_absolute_path();
        test_archive_dir();
        test_archive_dir_file();
        test_archive_dot_path();
        test_archive_dot_slash_path();
        test_archive_symlink();
        test_archive_fifo();
        test_archive_char();
        test_archive_data_align();
        test_archive_data_align_off();
        test_archive_data_align_off_bad();
        test_archive_hardlinks_order();
        test_archive_hardlinks_empty();
        test_archive_hardlinks_missing();
        test_archive_hardlinks_multi();
        test_archive_duplicates();
        test_archive_hardlink_duplicates();
        test_archive_list_separator();
        test_archive_fixed_mtime();
        test_archive_stat_mtime();
        test_archive_fixed_owner();
        test_archive_stat_owner();
        test_archive_dev_maj_min();
    }
}
