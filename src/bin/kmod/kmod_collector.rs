// kmod_collector.rs
use super::kmod_iterator::KmodModuleListIter;
use super::kmod_wrappers::{KmodContext, KmodModule};
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

// FFI bindings are placed here as the top-level module where unsafe is permitted.
// --- FFI BINDINGS ---
// these are the direct C function calls we map from libkmod.so.2.
// they are all 'unsafe' and must only be called from within our safe wrappers.

pub mod ffi_bindings {
    // declare Kmod structs here for use in wrappers/iterator
    #[repr(C)]
    pub struct kmod_ctx {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct kmod_module {
        _private: [u8; 0],
    }
    #[repr(C)]
    pub struct kmod_list {
        _private: [u8; 0],
    }
    pub const KMOD_MODULE_LIVE: i32 = 1;
    pub const KMOD_MODULE_BUILTIN: i32 = 0;

    // #[allow(improper_ctypes)] // suppress warning for opaque pointers
    #[link(name = "kmod")]
    unsafe extern "C" {
        // all ffi bindings from libkmod public api

        // kmod-context management
        pub unsafe fn kmod_new(root: *const i8, config: *const i8) -> *mut kmod_ctx;
        pub unsafe fn kmod_unref(ctx: *mut kmod_ctx);

        // lookup and ref/unref(counter)
        pub unsafe fn kmod_module_new_from_name_lookup(
            ctx: *mut kmod_ctx,
            modname: *const i8,
            mod_ptr: *mut *mut kmod_module,
        ) -> i32;
        pub unsafe fn kmod_module_get_module(entry: *const kmod_list) -> *mut kmod_module;
        // pub unsafe fn kmod_module_ref(mod_ptr: *mut kmod_module);
        pub unsafe fn kmod_module_unref(mod_ptr: *mut kmod_module);

        // List iteration and cleanup
        // #define kmod_list_foreach(curr, list) \
        //     for (curr = list; curr != NULL; curr = kmod_list_next(list, curr))
        pub unsafe fn kmod_list_next(
            list: *const kmod_list,
            current: *const kmod_list,
        ) -> *mut kmod_list;
        pub unsafe fn kmod_module_unref_list(list: *mut kmod_list);

        // Collect Dependencies
        // hard dependencies
        pub unsafe fn kmod_module_get_dependencies(mod_ptr: *const kmod_module) -> *mut kmod_list;

        // soft dependencies (pre: post:)
        pub unsafe fn kmod_module_get_softdeps(
            mod_ptr: *const kmod_module,
            pre: *mut *mut kmod_list,
            post: *mut *mut kmod_list,
        ) -> i32;

        // weak dependencies
        pub unsafe fn kmod_module_get_weakdeps(
            mod_ptr: *const kmod_module,
            weak: *mut *mut kmod_list,
        ) -> i32;

        // Get module information
        pub unsafe fn kmod_module_get_name(mod_ptr: *const kmod_module) -> *const i8;
        pub unsafe fn kmod_module_get_path(mod_ptr: *const kmod_module) -> *const i8;
        // int state = kmod_module_get_initstate(mod);
        pub unsafe fn kmod_module_get_initstate(mod_ptr: *const kmod_module) -> i32;
        // status_str = kmod_module_initstate_str(state);
        pub unsafe fn kmod_module_initstate_str(state: i32) -> *const i8;
        //
    }
}

// --- KmodCollector ---
// object flow: this is the main logic engine; it holds the context and runs the deps search.
// ownership: owns the long-lived KmodContext.
pub struct KmodCollector {
    context: KmodContext,
}

impl KmodCollector {
    pub fn new() -> Result<Self, String> {
        let context: KmodContext = KmodContext::new()?;
        Ok(KmodCollector { context })
    }

    pub fn get_context_ref(&self) -> &KmodContext {
        &self.context
    }

    // this runs all module dependencies (hard, soft, weak) recursively.
    // it returns a unique set of names.
    pub fn collect_recursive_dependencies(
        &self,
        initial_modules: &[(String, Option<String>)],
    ) -> Result<HashSet<String>, String> {
        let mut collected: HashSet<String> =
            initial_modules.iter().map(|(s, _)| s.clone()).collect();
        let mut queue: VecDeque<String> = initial_modules.iter().map(|(s, _)| s.clone()).collect();

        while let Some(current_mod_name) = queue.pop_front() {
            let target_mod = match KmodModule::find(&self.context, &current_mod_name) {
                Ok(m) => m,
                Err(_) => {
                    continue;
                } // skip missing modules
            };

            // Process all hard, soft, weak dependency types
            let mut iterators: Vec<KmodModuleListIter> = vec![target_mod.hard_dependencies()];
            if let Ok(soft_deps) = target_mod.soft_dependencies() {
                iterators.push(soft_deps.pre);
                iterators.push(soft_deps.post);
            }
            if let Ok(weak_deps_iter) = target_mod.weak_dependencies() {
                iterators.push(weak_deps_iter);
            }

            for iter in iterators {
                for dep_mod in iter {
                    let dep_name = dep_mod.get_name();
                    // if we find a new, unique module, add it to the collection and the queue for nested traversal
                    if collected.insert(dep_name.clone()) {
                        // recursive dependency checking for kernel modules isn't needed.
                        // each modules.dep line includes all (inc. transitive)
                        // dependencies for a given module, not just the immediate ones
                        // queue.push_back(dep_name);
                    }
                }
            }
        }

        Ok(collected)
    }

    // once we have all the names, this function gets the actual
    // paths needed for archiving into the initrd. we must filter out built-in modules here.
    pub fn collect_recursive_dependencies_paths(
        &self,
        initial_modules: &[(String, Option<String>)],
    ) -> Result<Vec<PathBuf>, String> {
        let module_names = self.collect_recursive_dependencies(initial_modules)?;
        let mut paths: Vec<PathBuf> = Vec::new();

        for mod_name in module_names {
            let target_mod = match KmodModule::find(&self.context, &mod_name) {
                Ok(m) => m,
                Err(_) => continue, // skip if lookup fails
            };

            let status = target_mod.get_status();
            let path_str = target_mod.get_path();

            let is_builtin_status = status == "builtin-kernel-module";

            // If the module is NOT built-in AND has a valid path string (not the placeholder), include it.
            if !is_builtin_status && path_str != "(built-in/not found)" {
                paths.push(PathBuf::from(path_str));
            }
        }

        Ok(paths)
    }
}
// --- end of KmodCollector implementation ---
