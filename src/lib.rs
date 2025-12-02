// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE LLC
use std::io;
use std::fs;
use std::collections::HashMap;

// parse /proc/version string, e.g. Linux version 6.17.0-2-default ...
fn host_kernel_vers_parse(kvers: &[u8]) -> io::Result<String> {
    match str::from_utf8(kvers) {
        Err(_) => Err(io::Error::from(io::ErrorKind::InvalidData)),
        Ok(s) => match s.strip_prefix("Linux version ") {
            None => Err(io::Error::from(io::ErrorKind::InvalidData)),
            Some(rel) => match rel.split_once([' ']) {
                Some((rel, _)) => Ok(rel.to_string()),
                None => Err(io::Error::from(io::ErrorKind::InvalidData)),
            },
        },
    }
}

// return the host kernel version based on /proc/version contents
pub fn host_kernel_vers() -> io::Result<String> {
    let kvers = fs::read("/proc/version")?;
    host_kernel_vers_parse(&kvers)
}

pub fn conf_src_or_host_kernel_vers(
    conf: &HashMap<String, String>
) -> io::Result<String> {
    match conf.get("KERNEL_SRC") {
        Some(ksrc) => {
            let b = fs::read(format!("{ksrc}/include/config/kernel.release"))?;
            let btrimmed = match b.strip_suffix(&[b'\n']) {
                Some(bt) => bt,
                None => &b,
            };
            Ok(String::from_utf8_lossy(btrimmed).to_string())
        },
        None => match conf.get("KERNEL_RELEASE") {
            Some(krel) => Ok(krel.clone()),
            None => host_kernel_vers(),
        },
    }
}

// return kmod dependencies based on @has_net and rapido @conf qemu parameters
pub fn conf_kmod_deps(conf: &HashMap<String, String>, has_net: bool) -> Vec<&str> {
    let mut deps = vec!();

    match conf.get("QEMU_EXTRA_ARGS") {
        Some(v) if v.contains("virtio-rng-pci") => deps.push("virtio_rng"),
        Some(_) | None => {},
    };

    if conf.get("VIRTFS_SHARE_PATH").is_some() {
        deps.extend(&["9pnet", "9pnet_virtio", "9p"]);
    }

    if has_net {
	deps.extend(&["virtio_net", "af_packet"]);
    }

    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_kernel_vers_parse() {
        let line = b"Linux version 6.17.0-2-default (geeko@buildhost) (gcc (SUSE Linux) 15.2.0, GNU ld (GNU Binutils; openSUSE Tumbleweed) 2.43.1.20241209-10) #1 SMP PREEMPT_DYNAMIC Thu Oct  2 08:12:40 UTC 2025 (190326b)";
        assert_eq!(host_kernel_vers_parse(line).unwrap(), "6.17.0-2-default");
    }

    #[test]
    fn test_conf_kmod_deps() {
        let conf: HashMap<String, String> = HashMap::from([
            ("QEMU_EXTRA_ARGS".to_string(), "-device virtio-rng-pci".to_string())
        ]);
        let kmods = conf_kmod_deps(&conf, true);
        assert!(kmods.contains(&"virtio_rng"));
        assert!(kmods.contains(&"virtio_net"));
    }
}
