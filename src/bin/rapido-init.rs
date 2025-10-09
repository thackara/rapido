// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE LLC
use std::io;
use std::fs;
use std::collections::HashMap;
use std::process::Command;
use std::str;

// we expect it in root on VMs
const RAPIDO_CONF: &str = "/rapido.conf";

#[derive(PartialEq)]
#[derive(Debug)]
struct KcliArgs<'a> {
    rapido_hostname: Option<&'a str>,
    rapido_vm_num: Option<&'a str>,
    rapido_tap_mac: Option<HashMap<&'a str, &'a str>>,
    systemd_machine_id: Option<&'a str>,
}

fn kcli_parse(kcmdline: &[u8]) -> io::Result<KcliArgs> {
    let mut args = KcliArgs {
        rapido_hostname: None,
        rapido_vm_num: None,
        rapido_tap_mac: None,
        systemd_machine_id: None,
    };

    // We know exactly what we're looking for, so don't bother with flexible
    // parsing via e.g. kv-conf.
    // It'd be nice if we could construct these match arrays at compile time
    // from the corresponding "key = " strings. For now they're vim compiled
    // via: s/\(.\)/b'\1', /g

    for w in kcmdline.split(|c| matches!(c, b' ')) {
        match w {
            // rapido.hostname
            [b'r', b'a', b'p', b'i', b'd', b'o', b'.',
            b'h', b'o', b's', b't', b'n', b'a', b'm', b'e', b'=', val @ ..] => {
                args.rapido_hostname = match str::from_utf8(val) {
                    Err(_) => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    },
                    Ok(s) => Some(s),
                };
            },
            // rapido.vm_num
            [b'r', b'a', b'p', b'i', b'd', b'o', b'.',
            b'v', b'm', b'_', b'n', b'u', b'm', b'=', val @ ..] => {
                args.rapido_vm_num = match str::from_utf8(val) {
                    Err(_) => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    },
                    Ok(s) => Some(s),
                };

            },
            // rapido.mac.<tap>=<mac>
            [b'r', b'a', b'p', b'i', b'd', b'o', b'.',
            b'm', b'a', b'c', b'.', tap_mac_kv @ ..] => {
                let (tap, mac) = match str::from_utf8(tap_mac_kv) {
                    Err(_) => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    },
                    Ok(s) if !s.contains('=') => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    },
                    Ok(s) => s.split_once('=').unwrap(),
                };
                let map = match args.rapido_tap_mac {
                    None => HashMap::from([ (tap, mac) ]),
                    Some(mut m) => {
                        m.insert(tap, mac);
                        m
                    },
                };
                args.rapido_tap_mac = Some(map);
            },
            // systemd.machine_id
            [b's', b'y', b's', b't', b'e', b'm', b'd', b'.',
            b'm', b'a', b'c', b'h', b'i', b'n', b'e', b'_', b'i', b'd', b'=',
            val @ ..] => {
                args.systemd_machine_id = match str::from_utf8(val) {
                    Err(_) => {
                        return Err(io::Error::from(io::ErrorKind::InvalidData));
                    },
                    Ok(s) => Some(s),
                };
            },
            [ _unused @ .. ] => {},
        };
    }

    Ok(args)
}

fn kmods_load(conf: &HashMap<String, String>) -> io::Result<()> {
    let mut modprobe_args: Vec<&str> = vec!("-a");

    match conf.get("QEMU_EXTRA_ARGS") {
        Some(v) => {
            if v.contains("virtio-rng-pci") {
                modprobe_args.push("virtio-rng");
            }
        },
        None => {},
    };

    if conf.get("VIRTFS_SHARE_PATH").is_some() {
        modprobe_args.extend(&["9pnet", "9pnet_virtio", "9p"]);
    }

    if modprobe_args.len() > 1 {
        let status = Command::new("modprobe")
            .args(&modprobe_args)
            .status()
            .expect("failed to execute process");
        if !status.success() {
            println!("modprobe failed");
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
    }

    Ok(())
}

fn main() -> io::Result<()> {
    let f = match fs::File::open(RAPIDO_CONF) {
        Ok(f) => f,
        Err(e) => {
            println!("failed to open {}: {}", RAPIDO_CONF, e);
            return Err(e);
        },
    };
    let mut reader = io::BufReader::new(f);
    let conf = match kv_conf::kv_conf_process(&mut reader) {
        Ok(c) => c,
        Err(e) => {
            println!("failed to process {}: {:?}", RAPIDO_CONF, e);
            return Err(e);
        },
    };
    kmods_load(&conf)?;

    let kcmdline = fs::read("/proc/cmdline")?;
    let kcli_args = kcli_parse(&kcmdline)?;

    if kcli_args.rapido_vm_num.is_none() {
        println!("/proc/cmdline missing rapido.vm_num");
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcli_parse() {
        let kcli = b"rapido.vm_num=3";
        assert_eq!(
            kcli_parse(kcli).expect("kcli_parse failed"),
            KcliArgs {
                rapido_vm_num: Some("3"),
                rapido_hostname: None,
                rapido_tap_mac: None,
                systemd_machine_id: None,
            }
        );

        let kcli = b"rapido.vm_num=3  rapido.hostname=rapido1 rapido.vm_num=4";
        assert_eq!(
            kcli_parse(kcli).expect("kcli_parse failed"),
            KcliArgs {
                rapido_vm_num: Some("4"),
                rapido_hostname: Some("rapido1"),
                rapido_tap_mac: None,
                systemd_machine_id: None,
            }
        );

        let kcli = b"rapido.mac.tap1=b8:ac:24:45:c5:01 rapido.mac.tap2=b8:ac:24:45:c5:02";
        assert_eq!(
            kcli_parse(kcli).expect("kcli_parse failed"),
            KcliArgs {
                rapido_vm_num: None,
                rapido_hostname: None,
                rapido_tap_mac: Some(HashMap::from([
                        ("tap1", "b8:ac:24:45:c5:01"),
                        ("tap2", "b8:ac:24:45:c5:02"),
                ])),
                systemd_machine_id: None,
            }
        );
    }
}
