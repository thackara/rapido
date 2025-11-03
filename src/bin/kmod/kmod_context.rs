// SPDX-License-Identifier: (GPL-2.0 OR GPL-3.0)
// Copyright (C) 2025 SUSE S.A.
use std::collections::HashMap;
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

        let ctx = KmodContext {
            modules_hash: HashMap::new(),
            alias_map: HashMap::new(),
            module_root: module_root,
        };

        println!(
            "Loading module database from: {}",
            ctx.module_root.display()
        );

        Ok(ctx)
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

    #[test]
    fn test_new_with_valid_dir() {
        let root_path = setup_test_dir("test_new_success");
        let root_dir_str = root_path.to_str().unwrap();

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
}
