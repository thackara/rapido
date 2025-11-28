// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE S.A.
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process;

mod kmod_context;
use kmod_context::{KmodContext, KmodModule, ModuleStatus, MODULE_DB_FILES};

struct CliArgs {
    pub module_names: Vec<String>,
    pub kmod_dir: Option<String>,
}

fn print_usage() {
    // TEST: cargo run --bin kmod -- --install-kmod 'xfs ext4 btrfs' [--kmod-dir MODULE_PATH]
    eprintln!("Usage: kmod-parser [OPTIONS]");
    eprintln!("\nOptions:");
    eprintln!("  --install-kmod MODULES Space separated list of kernel modules to install with dependencies.");
    eprintln!(
        "  --kmod-dir MODULE_PATH Specify the root path for modules (ex: /lib/modules/x.y.z)."
    );
    eprintln!("  -h, --help           Print help message.");
}

fn parse_all_args() -> Result<CliArgs, String> {
    let mut args_iter = env::args().skip(1);

    let mut parsed_args: CliArgs = CliArgs {
        module_names: Vec::new(),
        kmod_dir: None,
    };

    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err("PrintHelp".to_string()),
            "--install-kmod" => {
                if let Some(value) = args_iter.next() {
                    let kmod_names: Vec<String> =
                        value.split_whitespace().map(|s| s.to_string()).collect();
                    parsed_args.module_names.extend(kmod_names);
                }
            }

            "--kmod-dir" => {
                if let Some(value) = args_iter.next() {
                    parsed_args.kmod_dir = Some(value);
                }
            }
            _ => {
                return Err(format!(
                    "Unknown argument or positional argument not allowed: {}",
                    arg
                ));
            }
        }
    }
    Ok(parsed_args)
}

fn print_dep_line(dep_mod: &KmodModule, prefix: &str) {
    let dep_icon = if prefix == "harddep" {
        "├──"
    } else {
        "├────"
    };
    println!(
        "  {dep_icon} {prefix}: {} ({:?})",
        dep_mod.name(), dep_mod.status
    );
}

fn print_direct_deps(context: &KmodContext, root_name: &str) {
    let root_mod = match context.find(root_name) {
        Some(m) => m,
        None => {
            println!("🔗 {} (NotFound)", root_name);
            return;
        }
    };

    println!("🔗 {} ({:?})", root_mod.name(), root_mod.status);

    for dep_mod_name in &root_mod.hard_deps {
        if let Some(dep_mod) = context.find(dep_mod_name) {
            print_dep_line(dep_mod, "harddep");
        }
    }

    let soft_weak_deps_names = root_mod
        .soft_deps_pre
        .iter()
        .chain(root_mod.soft_deps_post.iter())
        .chain(root_mod.weak_deps.iter());

    for dep_mod_name in soft_weak_deps_names {
        if let Some(dep_mod) = context.find(dep_mod_name) {
            print_dep_line(dep_mod, "softdep");
        }
    }
}

fn print_dependency_graph(context: &KmodContext, initial_modules: &[String]) {
    println!("\n--- Dependency Graph (Tree) ---");
    for name in initial_modules {
        print_direct_deps(context, name);
    }
    println!("-------------------------------------------");
}

fn print_paths_summary(title: &str, paths: Result<Vec<PathBuf>, String>) {
    match paths {
        Ok(mut paths) => {
            println!("\n--- {} ({} found) ---", title, paths.len());
            paths.sort();
            for path in paths {
                println!("{}", path.display());
            }
            println!("------------------------------------------------------");
        }
        Err(e) => eprintln!("Error during {} collection: {}", title, e),
    }
}

fn collect_dependencies<'a>(
    context: &'a KmodContext,
    modules: &[String],
) -> Result<Vec<&'a KmodModule>, String> {
    let mut collected: HashMap<String, &KmodModule> = HashMap::new();

    for name in modules {
        if let Some(kmodule) = context.find(name) {
            let all_deps: Vec<&String> = kmodule
                .hard_deps
                .iter()
                .chain(kmodule.soft_deps_pre.iter())
                .chain(kmodule.soft_deps_post.iter())
                .chain(kmodule.weak_deps.iter())
                .collect();
            for dep_mod_name in all_deps {
                if let Some(dep_mod) = context.find(dep_mod_name) {
                    collected.entry(dep_mod_name.clone()).or_insert(dep_mod);
                }
            }
            collected.entry(kmodule.name()).or_insert(kmodule);
        }
    }
    Ok(collected.into_values().collect())
}

fn collect_module_paths(context: &KmodContext, modules: &[String]) -> Result<Vec<PathBuf>, String> {
    let paths: HashSet<PathBuf> = collect_dependencies(context, modules)?
        .into_iter()
        // filter out built-in modules
        .filter(|kmod| kmod.status != ModuleStatus::Builtin)
        // filter out if path exists
        .filter(|kmod| context.module_root.join(&kmod.rel_path).exists())
        .map(|kmod| context.module_root.join(&kmod.rel_path))
        .collect();

    Ok(paths.into_iter().collect())
}

fn collect_module_data_paths(context: &KmodContext) -> Result<Vec<PathBuf>, String> {
    let root = &context.module_root;
    let mut paths: Vec<PathBuf> = Vec::new();

    for file_name in MODULE_DB_FILES.iter() {
        let path = root.join(file_name);
        if path.is_file() {
            paths.push(path);
        }
    }

    Ok(paths)
}

fn collect_all_initrd_paths(
    context: &KmodContext,
    initial_modules: &[String],
) -> Result<Vec<PathBuf>, String> {
    let mut all_paths = collect_module_paths(context, initial_modules)?;
    let mut data_paths = collect_module_data_paths(context)?;
    all_paths.append(&mut data_paths);
    Ok(all_paths)
}

fn main() {
    let args = match parse_all_args() {
        Ok(res) => res,
        Err(e) if e == "PrintHelp" => {
            print_usage();
            process::exit(0);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            print_usage();
            process::exit(1);
        }
    };

    let initial_modules = args.module_names;
    let kmod_dir = match args.kmod_dir {
        None => {
            print_usage();
            process::exit(0);
        },
        Some(d) => d,
    };

    if initial_modules.is_empty() {
        print_usage();
        process::exit(0);
    }

    println!("--- Starting dependency collection ---");
    println!("Initial modules: {:?}", initial_modules);

    // The KmodContext::new logic handles the kernel directory derivation based on kmod_dir
    match KmodContext::new(&Path::new(&kmod_dir)) {
        Ok(context) => {
            print_dependency_graph(&context, &initial_modules);

            // Collect module names
            match collect_dependencies(&context, &initial_modules) {
                Ok(modules) => {
                    println!(
                        "\n--- Collected UNIQUE module names ({} found) ---",
                        modules.len()
                    );
                    for module in modules {
                        println!("  - {}: {:?}", module.name(), module.status);
                    }
                }
                Err(e) => eprintln!("Error during name collection: {}", e),
            }

            print_paths_summary(
                "Required loadable module paths",
                collect_module_paths(&context, &initial_modules),
            );

            print_paths_summary(
                "Required module data paths",
                collect_module_data_paths(&context),
            );

            print_paths_summary(
                "Required Initrd paths (loadable + data)",
                collect_all_initrd_paths(&context, &initial_modules),
            );
        }
        Err(e) => {
            eprintln!("\nInitialization error: {}", e);
            eprintln!("Check if kernel directory exists or use --kmod-dir to specify.");
            process::exit(1);
        }
    }
}
