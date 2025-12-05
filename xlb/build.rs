use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "xlb-ebpf")
        .ok_or_else(|| anyhow!("xlb-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let manifest_path = manifest_path.into_std_path_buf();
    let ebpf_root = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {}", manifest_path.display()))?
        .to_path_buf();

    let force_build = env::var_os("CARGO_FEATURE_BUILD_EBPF").is_some()
        || env::var("PROFILE").map(|p| p == "test").unwrap_or(false);

    if !force_build {
        if let Ok(src_obj) = locate_prebuilt_obj(&ebpf_root) {
            copy_to_out_dir(src_obj)?;
            return Ok(());
        } else {
            println!("cargo:warning=no prebuilt eBPF object found; building with aya-build");
        }
    }

    build_ebpf_package(name.as_str(), &ebpf_root)
}

fn copy_to_out_dir(src_obj: PathBuf) -> anyhow::Result<()> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    fs::create_dir_all(&out_dir)?;
    fs::copy(&src_obj, out_dir.join("xlb-bpf"))?;
    println!("cargo:rerun-if-env-changed=XLB_EBPF_OBJECT");
    println!("cargo:rerun-if-changed={}", src_obj.display());
    Ok(())
}

fn build_ebpf_package(name: &str, ebpf_root: &Path) -> anyhow::Result<()> {
    let features = ["build-ebpf"];
    let package = aya_build::Package {
        name,
        root_dir: ebpf_root
            .to_str()
            .ok_or_else(|| anyhow!("invalid path {}", ebpf_root.display()))?,
        features: &features,
        ..Default::default()
    };
    aya_build::build_ebpf([package], Toolchain::default())
}

fn locate_prebuilt_obj(ebpf_root: &Path) -> anyhow::Result<PathBuf> {
    if let Some(path) = env::var_os("XLB_EBPF_OBJECT") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
        return Err(anyhow!(
            "XLB_EBPF_OBJECT points to {}, but the file does not exist",
            path.display()
        ));
    }

    let candidates = [
        ebpf_root
            .join("target")
            .join("bpfel-unknown-none")
            .join("release")
            .join("xlb-bpf"),
        ebpf_root
            .join("target")
            .join("bpfel-unknown-none")
            .join("debug")
            .join("xlb-bpf"),
    ];

    for candidate in candidates {
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "prebuilt eBPF object not found. \
         Run `cargo +nightly build -p xlb-ebpf --release --features build-ebpf --target bpfel-unknown-none` \
         (or set XLB_EBPF_OBJECT to the compiled object) before building the userspace binary."
    ))
}
