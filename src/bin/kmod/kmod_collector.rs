// kmod_collector.rs

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
