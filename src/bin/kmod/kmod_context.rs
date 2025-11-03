// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE S.A.
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::path::PathBuf;

// --- Module Data Structures ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModuleStatus {
    Builtin,
    LoadableModule,
    NotFound,
}

#[derive(Debug, Clone)]
pub struct KmodModule {
    pub name: String,
    pub status: ModuleStatus,
    pub path: PathBuf,
    pub hard_deps: Vec<String>,
    pub soft_deps_pre: Vec<String>,
    pub soft_deps_post: Vec<String>,
    pub weak_deps: Vec<String>,
}

// --- Context and APIs ---

pub struct KmodContext {
    modules_hash: HashMap<String, KmodModule>,
    alias_map: HashMap<String, String>,
    pub module_root: PathBuf,
}

fn read_lines<P: AsRef<Path>>(filename: P) -> io::Result<io::Lines<BufReader<File>>> {
    let file = File::open(filename)?;
    Ok(BufReader::new(file).lines())
}

// extract: from _path: 'kernel/sub/module.ko{.xz,.zst,.gz}' -> name: 'module'
fn extract_module_name(path_str: &str) -> String {
    let path = PathBuf::from(path_str);
    // file_stem: 'kernel/sub/module.ko{.xz,.zst,.gz}' -> file_stem: 'module{.ko}'
    let file_stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path_str);

    // file_stem_strip_suffix: 'module{.ko}' -> name: 'module'
    let base_name = file_stem.strip_suffix(".ko").unwrap_or(file_stem);
    // aligns with libkmod: 'kmod_module_get_name' logic.
    // name is always normalized (dashes are replaced with underscores).
    base_name.replace('-', "_")
}

impl KmodContext {
    pub fn new(dirname: Option<&str>) -> Result<Self, String> {
        let module_root: PathBuf = match dirname {
            Some(dir) => PathBuf::from(dir),
            None => {
                return Err(
                    "Kernel module directory (via rapido.conf: KERNEL_INSTALL_MOD_PATH) must be provided.".to_string()
                );
            }
        };

        let mut ctx = KmodContext {
            modules_hash: HashMap::new(),
            alias_map: HashMap::new(),
            module_root: module_root,
        };

        println!(
            "Loading module database from: {}",
            ctx.module_root.display()
        );

        // load modules.dep
        ctx.load_hard_dependencies()
            .map_err(|e| format!("Failed to load modules.dep: {}", e))?;

        // load modules.softdep
        ctx.load_soft_dependencies()
            .map_err(|e| format!("Failed to load modules.softdep: {}", e))?;

        Ok(ctx)
    }

    // Parses **modules.dep** (hard dependencies and module paths).
    fn load_hard_dependencies(&mut self) -> io::Result<()> {
        let path = self.module_root.join("modules.dep");
        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("modules.dep not found at path: {}", path.display()),
            ));
        }

        for line in read_lines(&path)? {
            let line = line?;
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }

            let module_path_str = parts[0].trim();
            let module_name = extract_module_name(module_path_str);

            // Collect dependency names
            let dep_names: Vec<String> = parts[1]
                .trim()
                .split_whitespace()
                .map(|p| extract_module_name(p))
                .collect();

            // Insert or update module
            let full_path = self.module_root.join(module_path_str);
            let module = self
                .modules_hash
                .entry(module_name.clone())
                .or_insert_with(|| KmodModule {
                    name: module_name,
                    status: ModuleStatus::LoadableModule,
                    path: full_path.clone(),
                    hard_deps: Vec::new(),
                    soft_deps_pre: Vec::new(),
                    soft_deps_post: Vec::new(),
                    weak_deps: Vec::new(),
                });

            module.path = full_path;
            module.hard_deps = dep_names;
            module.status = ModuleStatus::LoadableModule;
        }

        Ok(())
    }

    // Parses **modules.softdep**
    fn load_soft_dependencies(&mut self) -> io::Result<()> {
        let path = self.module_root.join("modules.softdep");
        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("modules.softdep not found at path: {}", path.display()),
            ));
        }

        for line in read_lines(&path)? {
            let line = line?;
            // softdep mod_name pre: pre_mod1 pre_mod2 post: post_mod1
            let parts: Vec<&str> = line.split_whitespace().collect();

            if parts.len() < 3 || parts[0] != "softdep" {
                continue;
            }

            let module_name = parts[1].to_string();

            if let Some(module) = self.modules_hash.get_mut(&module_name) {
                let mut current_list = &mut module.soft_deps_pre;

                for &part in parts.iter().skip(2) {
                    match part {
                        "pre:" => current_list = &mut module.soft_deps_pre,
                        "post:" => current_list = &mut module.soft_deps_post,
                        _ => current_list.push(part.to_string()),
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    const TEST_ROOT_DIR: &str = "target/kmod_test_root";

    fn setup_test_dir(test_name: &str) -> PathBuf {
        let root_path = PathBuf::from(TEST_ROOT_DIR).join(test_name);
        if root_path.exists() {
            fs::remove_dir_all(&root_path).unwrap();
        }
        fs::create_dir_all(&root_path).unwrap();
        root_path
    }

    fn cleanup_test_dir(root_path: &PathBuf) {
        if root_path.exists() {
            fs::remove_dir_all(root_path).unwrap();
        }
    }

    fn write_test_file(base_path: &Path, filename: &str, content: &str) -> PathBuf {
        let path = base_path.join(filename);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        path
    }

    fn set_context(root_path: &Path) -> KmodContext {
        KmodContext {
            modules_hash: HashMap::new(),
            alias_map: HashMap::new(),
            module_root: root_path.to_path_buf(),
        }
    }

    #[test]
    fn test_new_with_valid_dir() {
        let root_path = setup_test_dir("test_new_success");
        let root_dir_str = root_path.to_str().unwrap();
        write_test_file(&root_path, "modules.dep", "");
        write_test_file(&root_path, "modules.softdep", "");

        match KmodContext::new(Some(root_dir_str)) {
            Ok(context) => {
                assert_eq!(context.module_root, root_path, "Module root path mismatch");
            }
            Err(e) => panic!("KmodContext::new failed unexpectedly on valid input: {}", e),
        }

        cleanup_test_dir(&root_path);
    }

    #[test]
    fn test_new_with_no_dir_error() {
        match KmodContext::new(None) {
            Err(e) => {
                assert!(
                    e.contains("must be provided"),
                    "Error message should indicate missing directory, got: {}",
                    e
                );
            }
            Ok(_) => panic!("KmodContext::new should have failed when dirname is None"),
        }
    }

    #[test]
    fn test_kmod_context_new_error() {
        let root_path = setup_test_dir("missing_dep_dir");
        let root_dir_str = root_path.to_str().unwrap();
        // modules.*dep is missing (first hit load_hard_dependencies)
        match KmodContext::new(Some(root_dir_str)) {
            Ok(_) => panic!("Context should fail because modules.dep is missing"),
            Err(e) => assert!(e.contains("modules.dep not found")),
        }
        cleanup_test_dir(&root_path);
    }

    #[test]
    fn test_extract_module_name() {
        // direct case
        assert_eq!(
            extract_module_name("drivers/sub1/sub2/sub3/module_name.ko.zst"),
            "module_name"
        );
        // different compression extensions
        assert_eq!(
            extract_module_name("drivers/sub1/sub2/sub3/module_name.ko.xz"),
            "module_name"
        );
        assert_eq!(
            extract_module_name("drivers/sub1/sub2/sub3/module_name.ko.zst"),
            "module_name"
        );
        // normalization
        assert_eq!(
            extract_module_name("drivers/sub1/sub2/sub3/module-name.ko.zst"),
            "module_name"
        );
        // No path and .ko suffix
        assert_eq!(extract_module_name("module_name"), "module_name");
        // full path provided
        assert_eq!(
            extract_module_name("/lib/modules/x.y.z/drivers/sub1/sub2/sub3/module-name.ko.zst"),
            "module_name"
        );
    }

    #[test]
    fn test_load_harddeps() {
        let root_path = setup_test_dir("harddeps");
        let mut ctx = set_context(&root_path);

        // define modules and hard dependencies
        let modules_dep_content = format!(
            "kernel/mod_a.ko: kernel/dep1.ko kernel/dep2.ko.xz\n\
             kernel/mod-b.ko:\n" // mod-b => mod_b
        );
        write_test_file(&root_path, "modules.dep", &modules_dep_content);
        write_test_file(&root_path, "kernel/dep1.ko", "");

        ctx.load_hard_dependencies().unwrap();

        // Check mod_a
        let mod_a = ctx.modules_hash.get("mod_a").expect("mod_a not found");
        assert_eq!(mod_a.status, ModuleStatus::LoadableModule);
        assert!(mod_a.path.ends_with("kernel/mod_a.ko"));
        assert_eq!(
            mod_a.hard_deps,
            vec!["dep1", "dep2"],
            "Hard deps for mod_a incorrect"
        );

        // Check mod_b (normalization and no deps)
        let mod_b = ctx.modules_hash.get("mod_b").expect("mod_b not found");
        assert_eq!(mod_b.status, ModuleStatus::LoadableModule);
        assert!(mod_b.path.ends_with("kernel/mod-b.ko"));
        assert!(mod_b.hard_deps.is_empty(), "mod_b should have no hard deps");

        cleanup_test_dir(&root_path);
    }

    #[test]
    fn test_load_softdeps() {
        let root_path = setup_test_dir("softdeps");
        let mut ctx = set_context(&root_path);

        // setup KmodContext with the KmodModule(direct|harddep) that will receive softdeps
        ctx.modules_hash.insert(
            "mod_a".to_string(),
            KmodModule {
                name: "mod_a".to_string(),
                status: ModuleStatus::LoadableModule,
                path: PathBuf::new(),
                hard_deps: Vec::new(),
                soft_deps_pre: Vec::new(),
                soft_deps_post: Vec::new(),
                weak_deps: Vec::new(),
            },
        );

        // Define soft dependencies
        let modules_softdep_content = format!(
            "softdep mod_a pre: softdep_pre_1 softdep_pre_2 post: softdep_post_1\n\
             softdep mod_b pre: softdep_b_pre post: softdep_b_post\n" // mod_b should be None as it's not setup with KmodModule
        );
        write_test_file(&root_path, "modules.softdep", &modules_softdep_content);

        ctx.load_soft_dependencies().unwrap();

        // Check mod_a
        let mod_a = ctx.modules_hash.get("mod_a").expect("mod_a not found");
        assert_eq!(
            mod_a.soft_deps_pre,
            vec!["softdep_pre_1", "softdep_pre_2"],
            "Soft pre-deps incorrect"
        );
        assert_eq!(
            mod_a.soft_deps_post,
            vec!["softdep_post_1"],
            "Soft post-deps incorrect"
        );

        // check that mod_b is None (as it was not setup with KmodModule struct)
        assert!(ctx.modules_hash.get("mod_b").is_none());

        cleanup_test_dir(&root_path);
    }
}
