// main.rs
use std::process;

// import wrappers, collector, iterator
mod kmod_collector;
mod kmod_iterator;
mod kmod_wrappers;

use kmod_collector::KmodCollector;
use kmod_wrappers::{KmodContext, KmodModule};

fn print_dependency_list<I>(header: &str, dependencies: I)
where
    I: IntoIterator<Item = KmodModule>,
{
    println!("\n{}", header);
    let mut count: i32 = 0;

    // Use the safe Rust iterator to traverse the C linked list.
    for dep_mod in dependencies.into_iter() {
        count += 1;
        println!("  - Module: {}", dep_mod.get_name());
        println!("    Status: {}", dep_mod.get_status());
        println!("    Path: {}", dep_mod.get_path());
    }

    if count == 0 {
        println!("  None found.");
    }
}

pub fn print_dependencies(context: &KmodContext, module_name: &str) -> Result<(), String> {
    let target_mod: KmodModule = KmodModule::find(context, module_name)?;
    let name = target_mod.get_name();

    println!("--- Target Module: {} ---", name);
    println!("Status: {}", target_mod.get_status());
    println!("Target Path: {}", target_mod.get_path());
    println!("--------------------------------");

    print_dependency_list("[A] Hard Dependencies (Required Modules):", target_mod.hard_dependencies());

    // soft
    match target_mod.soft_dependencies() {
        Ok(soft_deps) => {
            print_dependency_list("[B] Soft Dependencies (pre):", soft_deps.pre);
            print_dependency_list("[C] Soft Dependencies (post):", soft_deps.post);
        }
        Err(e) => eprintln!("Warning: Failed to retrieve soft dependencies: {}", e), 
    }

    // weak
    match target_mod.weak_dependencies() {
        Ok(weak_deps) => {
            print_dependency_list("[D] Weak Dependencies (Suggested Aliases):", weak_deps);
        }
        Err(e) => eprintln!("Warning: Failed to retrieve weak dependencies: {}", e),
    }

    Ok(())
}
fn main() {
    // the main function takes a module name and prints all its dependencies (hard, soft, weak)
    // using the KmodCollector engine.

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        eprintln!("usage: {} <module_name>", args[0]);
        process::exit(1);
    }

    let module_name = &args[1];

    // object flow: KmodCollector::new(): KmodCollector is created, starting the KmodContext lifetime.
    // collector is dropped when it goes out of scope, calling KmodContext::drop and releasing libkmod context.

    // print_dependencies (Optional)
    match KmodCollector::new() {
        Ok(collector) => {
            // object flow: collector uses print_dependencies to drive the iteration.
            // iterators are created and immediately dropped after the loops finish.
            let context_ref: &KmodContext= collector.get_context_ref();
            if let Err(e) = print_dependencies(context_ref, module_name) {
                eprintln!("error collecting dependencies for '{}': {}", module_name, e);
                process::exit(1);
            }
        }
        Err(e) => {
            // initialization error check (ex: libkmod.so.2 missing)
            eprintln!("initialization error: {}", e);
            process::exit(1);
        }
    }

    println!("--- BREAKER ---");

    // collect_recursive_dependencies_paths
    match KmodCollector::new() {
        Ok(collector) => {
            // object flow: collect_recursive_dependencies_paths handles the iterator traversal
            // and filters out built-in modules, returning only loadable file paths.
            match collector.collect_recursive_dependencies_paths(&vec![(module_name.clone(), None)]) {
                Ok(paths) => {
                    println!("--- Required Module Paths (Loadable Only) ---");
                    for path in paths {
                        println!("{}", path.display());
                    }
                    println!("--------------------------------------------");
                }
                Err(e) => eprintln!("error during collection: {}", e),
            }
        }
        Err(e) => eprintln!("initialization error: {}", e),
    }
}
