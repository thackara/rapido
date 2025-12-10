// build.rs
// discovers bundles.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RapidoConfig {
    pub autorun_script: Option<String>,
    pub output_path: Option<String>,
    pub resource_memory: Option<String>,
    pub resource_cpus: Option<u32>,
    pub networking_enabled: bool,
    pub install_bins: Vec<String>,
    pub install_kmods: Vec<String>,
    pub install_source_paths: Vec<String>,
    pub include_data: Vec<IncludeItem>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IncludeItem {
    pub source: String,
    pub destination: String,
}

#[derive(Debug)]
pub enum ConfigError {
    IoError(std::io::Error, PathBuf),
    MalformedSyntax {
        line_num: usize,
        line: String,
        file: PathBuf,
    },
    InvalidKey {
        line_num: usize,
        key: String,
        file: PathBuf,
    },
    SemanticError {
        line_num: usize,
        message: String,
        file: PathBuf,
    },
    VariableError {
        message: String,
    },
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error")
    }
}

pub fn parse_rcf_files(
    // only mock implemented now
    _paths: &[PathBuf],              // RCF|kv bundles paths
    _vars: &HashMap<String, String>, // host_vars, may be processed via kv_conf for vars substitution
) -> Result<RapidoConfig, ConfigError> {
    Ok(RapidoConfig {
        autorun_script: Some("autorun/simple_example.sh".to_string()),
        install_bins: vec!["bash".to_string(), "ls".to_string()], // format_vec_string
        install_kmods: vec!["xfs".to_string(), "btrfs".to_string(), "ext4".to_string()], // format_vec_string
        networking_enabled: false,
        ..RapidoConfig::default()
    })
}

// format Vec<String> => vec!["a".to_string(), "b".to_string(), ...]
fn format_vec_string(data: &Vec<String>) -> String {
    format!(
        r#"vec![{}]"#,
        data.iter()
            .map(|s| format!(r#""{}".to_string()"#, s))
            .collect::<Vec<String>>()
            .join(", ")
    )
}

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let rcf_dir = PathBuf::from("cut");

    let mut bundles_map: Vec<(String, PathBuf)> = Vec::new();
    println!("cargo:rerun-if-changed={}", rcf_dir.display());

    match fs::read_dir(&rcf_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.expect("Error reading directory entry");
                let path = entry.path();

                if path.is_file() && path.extension().map_or(false, |ext| ext == "rcf") {
                    let file_name = path
                        .file_stem()
                        .expect("RCF file missing stem")
                        .to_string_lossy()
                        .to_string();
                    bundles_map.push((file_name, path));
                }
            }
        }
        Err(e) => {
            eprintln!(
                "Warning: Failed to read RCF directory '{}': {}. Continuing with empty bundles.",
                rcf_dir.display(),
                e
            );
        }
    }

    let host_vars = HashMap::new();
    let mut config_data_entries = String::new();

    // process each bundle
    for (name, rcf_path) in bundles_map.iter() {
        println!("cargo:rerun-if-changed={}", rcf_path.display());

        // parse the RCF file
        let final_config = match parse_rcf_files(&vec![rcf_path.clone()], &host_vars) {
            Ok(conf) => conf,
            Err(e) => panic!("Configuration Parsing Error for {}: {}", name, e),
        };

        let rust_name = name.replace('-', "_");

        // constructor

        let bins_list = format_vec_string(&final_config.install_bins);
        let kmods_list = format_vec_string(&final_config.install_kmods);
        let autorun_script = final_config
            .autorun_script
            .as_ref()
            .map_or("None".to_string(), |s| {
                format!(r#"Some("{}".to_string())"#, s)
            });

        let data_entry = format!(
            r#"
            (
                "{name}",
                RapidoConfig {{
                    autorun_script: {autorun_script},
                    output_path: None,
                    resource_memory: None,
                    resource_cpus: None,
                    networking_enabled: {networking_enabled},
                    install_bins: {bins_list},
                    install_kmods: {kmods_list},
                    install_source_paths: Vec::new(),
                    include_data: Vec::new(),
                }}
            ),"#,
            name = rust_name,
            autorun_script = autorun_script,
            bins_list = bins_list,
            kmods_list = kmods_list,
            networking_enabled = final_config.networking_enabled,
        );
        config_data_entries.push_str(&data_entry);
    }

    // dump the binary content to config_embedded.rs
    let output_file_path = out_dir.join("config_embedded.rs");
    let generated_code = format!(
        r#"
        // Generated by build.rs at compile time
        // use RapidoConfig;  // assuming rapido-cut already includes this struct

        pub fn get_embedded_config_data() -> std::vec::Vec<(&'static str, RapidoConfig)> {{
            vec![
                {config_data_entries}
            ]
        }}

        pub fn load_embedded_bundle_config(bundle_name: &str) -> RapidoConfig {{
            let name = bundle_name.replace('-', "_");
            let data = get_embedded_config_data();

            for (key, config) in data.into_iter() {{
                if key == name {{
                    return config;
                }}
            }}
            panic!("No embedded config found for bundle: {{}}", bundle_name);
        }}
        "#,
        config_data_entries = config_data_entries
    );

    fs::write(&output_file_path, generated_code)
        .expect("Failed to write final embedded config file.");
}
