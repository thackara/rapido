// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE S.A.
use std::env;
use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let mut args = env::args_os();
    if args.len() != 2 {
        println!("Usage: lsinitramfs INITRAMFS");
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    // avoid BufReader: regular fh benchmarked slightly faster, despite fewer
    // syscalls: read(hdr)+read(name)+seek() vs read(hdr+name+readahead)+seek()
    let f = fs::OpenOptions::new().read(true).open(args.nth(1).unwrap())?;
    let mut archive_walker = cpio::archive_walk(f)?;
    while let Some(archive_ent) = archive_walker.next() {
        let archive_ent = archive_ent?;
        match str::from_utf8(&archive_ent.name) {
            Ok(s) => println!("{: <9} {}", archive_ent.md.len, s),
            Err(_) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
    Ok(())
}
