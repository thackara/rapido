// kmod_wrappers.rs
use super::kmod_collector::ffi_bindings::*;
use std::ffi::{CStr, CString};
use std::ptr;

// --- KmodContext ---
// object flow: created once at startup, holds the global state.
// ownership: owned by KmodCollector.
// lifetime: spans the entire dependency collection process.
// drop: calls kmod_unref() to clean up the C context.
pub struct KmodContext {
    pub raw: *mut kmod_ctx,
}

impl KmodContext {
    pub fn new() -> Result<Self, String> {
        let raw: *mut kmod_ctx = unsafe { kmod_new(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err("failed to initialize kmod context.".to_string());
        }
        Ok(KmodContext { raw })
    }
}

// when kmodcontext is dropped (goes out of scope), this function is called.
impl Drop for KmodContext {
    fn drop(&mut self) {
        unsafe {
            kmod_unref(self.raw);
        }
    }
}

// --- KmodModule ---
// object flow: created for each module we need to inspect (including dependencies).
// ownership: owned by the collector.
// lifetime: short-lived; exists just long enough to extract information or dependencies.
// drop: calls kmod_module_unref() to decrease the reference count.
pub struct KmodModule {
    pub raw: *mut kmod_module,
}

impl KmodModule {
    // this function looks up the module's details using its name
    // and returns the definitive, canonical module object.
    pub fn find(ctx: &KmodContext, name: &str) -> Result<Self, String> {
        let c_name = CString::new(name).map_err(|_| "invalid module name".to_string())?;
        let mut target_mod: *mut kmod_module = ptr::null_mut();
        // kmod_module_new_from_name_lookup returns a module with refcount=1
        let ret =
            unsafe { kmod_module_new_from_name_lookup(ctx.raw, c_name.as_ptr(), &mut target_mod) };
        if ret < 0 || target_mod.is_null() {
            return Err(format!(
                "module '{}' not found or lookup failed (code: {})",
                name, ret
            ));
        }

        Ok(KmodModule { raw: target_mod })
    }

    // --- info getters (read-only ffi calls) ---
    fn c_ptr_to_string(ptr: *const i8) -> String {
        if ptr.is_null() {
            "(built-in/not found)".to_string()
        } else {
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned()
        }
    }

    pub fn get_name(&self) -> String {
        let ptr: *const i8 = unsafe { kmod_module_get_name(self.raw) };
        Self::c_ptr_to_string(ptr)
    }

    pub fn get_path(&self) -> String {
        let ptr: *const i8 = unsafe { kmod_module_get_path(self.raw) };
        Self::c_ptr_to_string(ptr)
    }

    pub fn get_status(&self) -> String {
        let state: i32 = unsafe { kmod_module_get_initstate(self.raw) };
        let path: *const i8 = unsafe { kmod_module_get_path(self.raw) };
        if state == KMOD_MODULE_LIVE {
            "loaded-module".to_string()
        } else if state == KMOD_MODULE_BUILTIN {
            "builtin-kernel-module".to_string()
        } else if !path.is_null() {
            "loadable-module".to_string()
        } else {
            let state_str_ptr: *const i8 = unsafe { kmod_module_initstate_str(state) };
            Self::c_ptr_to_string(state_str_ptr)
        }
    }
}

// when kmodmodule is dropped, this function is called.
impl Drop for KmodModule {
    fn drop(&mut self) {
        unsafe {
            kmod_module_unref(self.raw); // refcount decrease
        }
    }
}
