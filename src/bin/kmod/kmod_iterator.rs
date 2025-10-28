// kmod_iterator.rs
use super::kmod_collector::ffi_bindings::*;
use super::kmod_wrappers::KmodModule;
use std::ptr;

// --- KmodModuleListIter ---
// object flow: created temporarily when retrieving dependencies (hard, soft, weak).
// ownership: owns the C list head pointer (self.head).
// lifetime: short-lived; exists only for the duration of the 'for' loop using it.
// drop: calls kmod_module_unref_list() on self.head.
pub struct KmodModuleListIter {
    pub current: *mut kmod_list,
    pub head: *mut kmod_list,
}

// this iterator is the safety barrier. it hides the unsafe
// pointer walking and makes sure that any developer using it gets clean, safe KmodModule objects.
impl KmodModuleListIter {
    pub fn new(head: *mut kmod_list) -> Self {
        if head.is_null() {
            // handles empty lists safely
            KmodModuleListIter {
                current: ptr::null_mut(),
                head: ptr::null_mut(),
            }
        } else {
            // we initialize 'current' to 'head' so the first call to next() advances us to the first element.
            KmodModuleListIter {
                current: head,
                head: head,
            }
        }
    }
}

impl Iterator for KmodModuleListIter {
    type Item = KmodModule;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            // 1. CHECK: kmod_list_next returns NULL when the list is exhausted.
            if self.current.is_null() {
                return None;
            }

            // 2. STORE: entry_to_process holds the address we must now extract the module from.
            let entry_to_process: *mut kmod_list = self.current;

            // 3. ADVANCE: use the current pointer to get the next one.
            // this is the core logic that moves us from the head node to the first dependency.
            self.current = kmod_list_next(self.head, entry_to_process);

            // 4. PROCESS: kmod_module_get_module for the entry_to_process
            // kmod_module_get_module returns an @entry in the list incrementing its refcount
            let dep_mod_ptr: *mut kmod_module = kmod_module_get_module(entry_to_process);

            if dep_mod_ptr.is_null() {
                // skip if libkmod didn't give us a module pointer,
                // we skip this entry and recurse to get the next one safely.
                return self.next();
            }

            // return the successfully found module
            // We transfer this ownership to the new KmodModule struct.
            Some(KmodModule { raw: dep_mod_ptr })
        }
    }
}

// when kmodmodulelistiter is dropped, this function is called.
impl Drop for KmodModuleListIter {
    fn drop(&mut self) {
        if !self.head.is_null() {
            unsafe {
                // provide the starting refernce for traversal in `kmod_list_release`
                kmod_module_unref_list(self.head); // clean up the allocated list
            }
        }
    }
}

// soft dependencies container
pub struct SoftDependencies {
    pub pre: KmodModuleListIter,
    pub post: KmodModuleListIter,
}
