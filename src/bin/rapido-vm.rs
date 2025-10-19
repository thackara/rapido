// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE LLC
use std::collections::HashMap;
use std::env;
use std::fs;
use std::hash::{DefaultHasher, Hasher};
use std::io::{self, BufRead};
use std::os::unix::fs::FileTypeExt;
use std::path;
use std::process;

fn vm_is_running(vm_pid_file: &str) -> io::Result<bool> {
    let mut pid = String::new();
    let n = match fs::File::open(vm_pid_file) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
        Ok(f) => io::BufReader::new(f).read_line(&mut pid)?,
    };

    let pid = pid.trim_end();
    if n < 1 || n > 16 || usize::from_str_radix(pid, 10).is_err() {
        eprintln!("bad qemu pid file data ({} bytes): {}", n, pid);
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    return match fs::symlink_metadata(&format!("/proc/{}", pid)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
        Ok(_) => Ok(true),
    };
}

// Generate a reproducible MAC address based on vm_num and vm_tap IDs.
// We can reuse the generic hashmap hash lib for this \o/
fn vm_mac_gen(vm_num: u64, vm_tap: &str) -> String {
    let mut hasher = DefaultHasher::new();
    hasher.write_u64(vm_num);
    hasher.write(vm_tap.as_bytes());
    let h: u64 = hasher.finish();
    format!("b8:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        h & 0xff, (h >> 8) & 0xff, (h >> 16) & 0xff, (h >> 24) & 0xff,
        (h >> 32) & 0xff)
}

struct VmResources {
    cpus: u32,
    mem: String,
    net: bool,
}

fn vm_resource_line_process(line: &[u8], rscs: &mut VmResources) -> io::Result<()> {
    match line {
        // vim compiled from string via: s/\(.\)/b'\1', /g
        // rapido-rsc/cpu/
        [b'r', b'a', b'p', b'i', b'd', b'o', b'-', b'r', b's', b'c', b'/',
         b'c', b'p', b'u', b'/', val @ ..] => {
            rscs.cpus = match str::from_utf8(val) {
                Ok(s) if s.parse::<u32>().is_ok() => s.parse::<u32>().unwrap(),
                Err(_) | Ok(_) => {
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                },
            };
        },
        // rapido-rsc/mem/
        [b'r', b'a', b'p', b'i', b'd', b'o', b'-', b'r', b's', b'c', b'/',
         b'm', b'e', b'm', b'/', val @ ..] => {
            rscs.mem = match str::from_utf8(val) {
                Err(_) => {
                    Err(io::Error::from(io::ErrorKind::InvalidData))
                },
                Ok(s) => {
                    match s.rsplit_once(['m', 'M', 'g', 'G']) {
                        None if s.parse::<u64>().is_ok() => Ok(s.to_string()),
                        Some((n, u)) if n.parse::<u64>().is_ok() && u == "" => {
                            Ok(s.to_string())
                        },
                        None | Some((_, _)) => {
                            Err(io::Error::from(io::ErrorKind::InvalidData))
                        },
                    }
                },
            }?;
        },
        // rapido-rsc/qemu/custom_args
        [b'r', b'a', b'p', b'i', b'd', b'o', b'-', b'r', b's', b'c', b'/',
         b'q', b'e', b'm', b'u', b'/',
         b'c', b'u', b's', b't', b'o', b'm', b'_', b'a', b'r', b'g', b's'] => {
             // obsolete way for images to inject their own qemu params.
             // cut scripts should instead assert that the args required are set.
             eprintln!("ignoring qemu custom_args presence");
        },
        // rapido-rsc/net
        [b'r', b'a', b'p', b'i', b'd', b'o', b'-', b'r', b's', b'c', b'/',
         b'n', b'e', b't'] => {
             rscs.net = true;
        },
        [ _unused @ .. ] => {},
    }

    Ok(())
}

fn vm_resources_get(initramfs_img: &str) -> io::Result<VmResources> {
    // rapido defaults
    let mut rscs = VmResources{
        cpus: 2,
        mem: "512M".to_string(),
        net: false,
    };

    // TODO extend cpio lib to list files and *seek* past data
    let mut proc = process::Command::new("cpio")
        .args(["--quiet", "--list", "rapido-rsc/*/*", "rapido-rsc/net"])
        .stdin(process::Stdio::piped())
        .stdout(process::Stdio::piped())
        .spawn()
        .expect("failed to execute process");
    {
        let f = fs::OpenOptions::new().read(true).open(&initramfs_img)?;
        let mut reader = io::BufReader::new(f);
        let mut stdin = proc.stdin.take().unwrap();
        match io::copy(&mut reader, &mut stdin) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
                eprintln!("ignoring EPIPE while copying to cpio - concat archive?");
            },
            Err(e) => {
                eprintln!("failed to copy all data to cpio: {:?}", e);
                return Err(e);
            },
            Ok(_) => {},
        }
    }
    let output = proc.wait_with_output()?;
    for line in output.stdout.split(|b| *b == b'\n') {
        vm_resource_line_process(line, &mut rscs)?;
    }

    Ok(rscs)
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

struct QemuArgs<'a>  {
    qemu_bin: &'a str,
    kernel_img: String,
    console: &'a str,
    params: Vec<&'a str>,
}

fn vm_qemu_args_get(conf: &HashMap<String, String>) -> io::Result<QemuArgs> {
    let mut params = vec!();
    let mut qemu_args: Option<QemuArgs> = None;

    //let (kconfig: String, krel: Option<&str>) = match conf.get("KERNEL_SRC") {
    let (kconfig, krel) = match conf.get("KERNEL_SRC") {
        Some(ks) => (format!("{ks}/.config"), None),
        None => match conf.get("KERNEL_RELEASE") {
            Some(rel) => (format!("/boot/config-{rel}"), Some(rel.clone())),
            None => {
                let kvers = fs::read("/proc/version")?;
                let rel = get_host_rel(&kvers)?;
                (format!("/boot/config-{rel}"), Some(rel.to_string()))
            },
        },
    };

    match fs::symlink_metadata("/dev/kvm") {
        Ok(md) if md.file_type().is_char_device() => {
            params.extend(["-machine", "accel=kvm"])
        },
        Err(_) | Ok(_) => {},
    };

    let ksrc = conf.get("KERNEL_SRC");

    let f = fs::OpenOptions::new().read(true).open(&kconfig)?;
    for line in io::BufReader::new(f).lines().map_while(Result::ok) {
        if line == "CONFIG_X86_64=y" {
            qemu_args = match ksrc {
                Some(ks) => Some(QemuArgs{
                    kernel_img: format!("{ks}/bzImage"),
                    qemu_bin: "qemu-system-x86_64",
                    console: "ttyS0",
                    params,
                }),
                None => Some(QemuArgs{
                    // krel always set without KERNEL_SRC
                    kernel_img: format!("/boot/vmlinuz-{}", krel.unwrap()),
                    qemu_bin: "qemu-system-x86_64",
                    console: "ttyS0",
                    params,
                }),
            };
            break;
        } else if line == "CONFIG_ARM64=y" {
            params.extend([
                "-machine", "virt,gic-version=host",
                "-cpu", "host"
            ]);
            qemu_args = match ksrc {
                Some(ks) => Some(QemuArgs{
                    kernel_img: format!("{ks}/arch/arm64/boot/Image"),
                    qemu_bin: "qemu-system-aarch64",
                    console: "ttyAMA0",
                    params,
                }),
                None => Some(QemuArgs{
                    kernel_img: format!("/boot/Image-{}", krel.unwrap()),
                    qemu_bin: "qemu-system-aarch64",
                    console: "ttyAMA0",
                    params,
                }),
            };
            break;
	} else if line == "CONFIG_PPC64=y" {
            qemu_args = match ksrc {
                Some(ks) => Some(QemuArgs{
                    kernel_img: format!("{ks}/arch/powerpc/boot/zImage"),
                    qemu_bin: "qemu-system-ppc64",
                    console: "hvc0",
                    params,
                }),
                None => Some(QemuArgs{
                    kernel_img: format!("/boot/vmlinux-{}", krel.unwrap()),
                    qemu_bin: "qemu-system-ppc64",
                    console: "hvc0",
                    params,
                }),
            };
            break;
	} else if line == "CONFIG_S390=y" {
            qemu_args = match ksrc {
                Some(ks) => Some(QemuArgs{
                    kernel_img: format!("{ks}/arch/s390/boot/bzImage"),
                    qemu_bin: "qemu-system-s390x",
                    console: "ttysclp0",
                    params,
                }),
                None => Some(QemuArgs{
                    kernel_img: format!("/boot/bzImage-{}", krel.unwrap()),
                    qemu_bin: "qemu-system-s390x",
                    console: "ttysclp0",
                    params,
                }),
            };
            break;
        }
    }

    if qemu_args.is_none() {
        eprintln!("architecture not yet supported, please add it");
        return Err(io::Error::from(io::ErrorKind::Unsupported));
    }

    let qemu_args = qemu_args.unwrap();
    if fs::symlink_metadata(&qemu_args.kernel_img).is_err() {
        eprintln!(
            "no kernel image present at {}, wrong detection or build needed",
            qemu_args.kernel_img
        );
        return Err(io::Error::from(io::ErrorKind::NotFound));
    }

    return Ok(qemu_args);
}

fn vm_start(vm_num: u64, vm_pid_file: &str, initramfs_img: &str, conf: &HashMap<String,String>) -> io::Result<()> {
    let mut qemu_args = vm_qemu_args_get(conf)?;
    let mut kcmdline = format!("console={} rapido.vm_num={}", qemu_args.console, vm_num);
    let net_conf_dir = format!(
        "{}/vm{}",
        conf.get("VM_NET_CONF").expect("VM_NET_CONF not set"),
        vm_num
    );

    match fs::read_to_string(format!("{net_conf_dir}/hostname")) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
        Err(e) => return Err(e),
        Ok(hn) => {
            kcmdline.push_str(&format!(" rapido.hostname={}", hn.trim_end()));
        },
    }

    let rscs = match vm_resources_get(&initramfs_img) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("no initramfs image at {initramfs_img}. Run \"cut_X\" script?");
            return Err(e);
        },
        Err(e) => return Err(e),
        Ok(r) => r,
    };

    let cpus = format!("{},sockets={},cores=1,threads=1", rscs.cpus, rscs.cpus);
    qemu_args.params.extend([
        "-smp", &cpus,
        "-m", &rscs.mem,
        "-kernel", &qemu_args.kernel_img,
        "-initrd", initramfs_img,
        "-pidfile", vm_pid_file,
    ]);

    // params is Vec<&str>, so stash generated net Strings elsewhere
    let mut net_params_stash: Vec<String> = vec!();

    if !rscs.net {
        qemu_args.params.extend(["-net", "none"]);
    } else {
        // networkd needs a hex unique ID (for dhcp leases, etc.)
        // TODO not sure about length, but vm.sh uses md5sum of vm_num, so
        // prepend some garbage :shrug:
        kcmdline.push_str(
            &format!(" net.ifnames=0 systemd.machine_id=2af1d0cafe2afid0{:016x}", vm_num)
        );

        let mut i = 0;
	for entry in fs::read_dir(&net_conf_dir)? {
            let entry = entry?;
            let path = entry.path();
            match path.extension() {
                None => continue,
                Some(e) if e.as_encoded_bytes() != b"network" => continue,
                Some(_) => {},
            }
            let vm_tap = match path.file_stem() {
                None => continue,
                Some(t) => match t.to_str() {
                    None => continue,
                    Some(t_str) => t_str,
                },
            };
            // Only attempt to add host IFF_TAP (0x02) devices as
            // qemu netdevs. This allows for extra VM virtual device
            // creation and configuration via net-conf.
            const IFF_TAP: usize = 0x02;
            let mut tp = path::PathBuf::from("/sys/class/net/");
            tp.push(vm_tap);
            tp.push("tun_flags");
            let tun_flags = match fs::read(&tp) {
                Err(_) => continue,
                Ok(flags) => match str::from_utf8(&flags) {
                    Err(_) => continue,
                    Ok(flags_str) => {
                        if let Some(s) = flags_str.strip_prefix("0x") {
                            usize::from_str_radix(s.trim_end(), 16)
                        } else {
                            eprintln!("{:?} missing expected 0x flags prefix", tp);
                            return Err(io::Error::from(io::ErrorKind::InvalidData));
                        }
                    },
                },
            };
            match tun_flags {
                Err(_) => {
                    eprintln!("unexpected tun_flags at {:?}", tp);
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                },
                Ok(flags_val) if flags_val & IFF_TAP != IFF_TAP => continue,
                Ok(_) => {},
            }

            let tap_mac = vm_mac_gen(vm_num, vm_tap);

            // TODO append net conf MAC [match] to cpio, instead of at boot
            // time via kcmdline.
            kcmdline.push_str(&format!(" rapido.mac.{vm_tap}={tap_mac}"));

            net_params_stash.extend([
              "-device".to_string(),
              format!("virtio-net,netdev=if{i},mac={tap_mac}"),
              "-netdev".to_string(),
              format!("tap,id=if{i},script=no,downscript=no,ifname={vm_tap}"),
            ]);
            i += 1;
        }
        if i == 0 {
            eprintln!("no valid TAP devices found in {net_conf_dir}");
        }
    }

    if let Some(kp) = conf.get("QEMU_EXTRA_KERNEL_PARAMS") {
        kcmdline.push_str(&format!(" {kp}"));
    }

    qemu_args.params.extend(["-append", &kcmdline]);

    let virtfs_sp: String;
    if let Some(vsp) = conf.get("VIRTFS_SHARE_PATH") {
        virtfs_sp = format!("local,path={vsp},mount_tag=host0,security_model=mapped,id=host0");
        qemu_args.params.extend(["-virtfs", &virtfs_sp]);
    }

    if let Some(qea) = conf.get("QEMU_EXTRA_ARGS") {
        qemu_args.params.extend(qea.split(&[' ', '\n']));
    }

    let mut spawned_vm = process::Command::new(qemu_args.qemu_bin)
        .args(qemu_args.params)
        .args(net_params_stash)
        .spawn()
        .expect("failed to execute qemu");
    match spawned_vm.wait() {
        Err(e) => {
            eprintln!("{} failed: {:?}", qemu_args.qemu_bin, e);
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        },
        Ok(status) if !status.success() => {
            eprintln!("{} exited with status: {}", qemu_args.qemu_bin, status);
            Ok(())
        },
        Ok(_) => Ok(()),
    }
}

fn vm_rapido_conf(rapido_dir: &str) -> io::Result<HashMap<String, String>> {
    let rapido_conf = format!("{}/rapido.conf", rapido_dir);
    // set a bunch of defaults, which may be overridden by rapido.conf
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

    let f = match fs::File::open(&rapido_conf) {
        Ok(f) => f,
        Err(e) => {
            println!("failed to open {}: {}", rapido_conf, e);
            return Err(e);
        },
    };
    let mut reader = io::BufReader::new(f);
    match kv_conf::kv_conf_process_append(&mut reader, &mut conf) {
        Ok(_) => {},
        Err(e) => {
            println!("failed to process {}: {:?}", rapido_conf, e);
            return Err(e);
        },
    };
    Ok(conf)
}

fn main() -> io::Result<()> {
    let cur_dir = env::current_dir()?;
    let rapido_dir = match cur_dir.to_str() {
        None => return Err(io::Error::from(io::ErrorKind::InvalidInput)),
        Some(s) => s,
    };

    let conf = vm_rapido_conf(rapido_dir)?;
    let pid_dir = conf.get("QEMU_PID_DIR").unwrap();
    let initramfs_img = conf.get("DRACUT_OUT").unwrap();

    // 1k rapido VM limit is arbitrary
    for vm_num in 1..1000 {
        let vm_pid_file = format!("{}/rapido_vm{}.pid", pid_dir, vm_num);
        if !vm_is_running(&vm_pid_file)? {
            return vm_start(vm_num, &vm_pid_file, &initramfs_img, &conf);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_resources_parse() {
        let line = b"rapido-rsc/cpu/5";
        let mut rscs = VmResources{
            cpus: 0,
            mem: String::new(),
            net: false,
        };
        assert!(vm_resource_line_process(line, &mut rscs).is_ok());
        assert_eq!(rscs.cpus, 5);

        let line = b"rapido-rsc/mem/5G";
        assert!(vm_resource_line_process(line, &mut rscs).is_ok());
        assert_eq!(rscs.mem, "5G");

        let line = b"rapido-rsc/mem/5m";
        assert!(vm_resource_line_process(line, &mut rscs).is_ok());
        assert_eq!(rscs.mem, "5m");

        let line = b"rapido-rsc/mem/5t";
        assert!(vm_resource_line_process(line, &mut rscs).is_err());

        let line = b"rapido-rsc/net";
        assert!(vm_resource_line_process(line, &mut rscs).is_ok());
        assert_eq!(rscs.net, true);
    }
}
