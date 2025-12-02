// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE LLC
use std::io;
use std::fs;
use std::collections::HashMap;
use std::path::PathBuf;

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

// set defaults and then read rapido.conf under @rapido_dir_path
pub fn conf_parse_from_defaults(
    mut rapido_dir_path: PathBuf
) -> io::Result<HashMap<String, String>> {
    let rapido_dir: &str = match rapido_dir_path.to_str() {
        None => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
        Some(s) => s,
    };

    let mut conf: HashMap<String, String> = HashMap::from([
        // Dracut initramfs output path and QEMU input
        ("DRACUT_OUT".to_string(), format!("{}/initrds/myinitrd", rapido_dir)),
        // default directory to write QEMU pidfiles
        ("QEMU_PID_DIR".to_string(), format!("{}/initrds", rapido_dir)),
        // default VM network config path, also used for tap provisioning
        ("VM_NET_CONF".to_string(), format!("{}/net-conf", rapido_dir)),
        // QEMU defaults: CLI with console redirection. Provide VMs with an RNG device.
        ("QEMU_EXTRA_ARGS".to_string(), "-nographic -device virtio-rng-pci".to_string()),
    ]);

    rapido_dir_path.push("rapido.conf");
    let f = match fs::File::open(&rapido_dir_path) {
        Ok(f) => f,
        Err(e) => {
            println!("failed to open {:?}: {}", rapido_dir_path, e);
            return Err(e);
        },
    };
    let mut reader = io::BufReader::new(f);
    match kv_conf::kv_conf_process_append(&mut reader, &mut conf) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("failed to process {:?}: {:?}", rapido_dir_path, e);
            return Err(e);
        },
    };
    Ok(conf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct TempDir {
        pub dir: PathBuf,
    }
    impl TempDir {
        // create a random temporary directory under CWD.
        // The directory will be cleaned up when TempDir goes out of scope.
        pub fn new() -> TempDir {
            let mut b = [0u8; 16];
            let mut dirname = String::from("test-rapido-lib-");
            fs::File::open("/dev/urandom").unwrap().read_exact(&mut b).unwrap();
            for i in &b {
                dirname.push_str(&format!("{:02x}", i));
            }

            fs::create_dir(&dirname).unwrap();
            eprintln!("created tmp dir: {}", dirname);
            TempDir { dir: PathBuf::from(dirname) }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            assert!(self.dir.is_dir());
            // scary but does not follow symlinks so should be okay
            fs::remove_dir_all(&self.dir).unwrap();
            eprintln!("removed tmp dir: {}", self.dir.display());
        }
    }

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

    #[test]
    fn test_conf_parse_from_defaults() {
        let td = TempDir::new();
        fs::write(td.dir.join("rapido.conf"), b"DRACUT_OUT=thisfile").unwrap();
        let c = conf_parse_from_defaults(td.dir.clone()).unwrap();
        // explicitly set by rapido.conf
        assert_eq!(c.get("DRACUT_OUT"), Some("thisfile".to_string()).as_ref());
        // set as default
        assert!(c.get("QEMU_EXTRA_ARGS").unwrap().contains("-nographic"));
    }
}
