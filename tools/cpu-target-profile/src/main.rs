use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use cpu_target_profile::{
    CpuTargetSelection, DestinationProfile, cargo_toml, cc_rs_flags_json, cmake_toolchain,
    meson_options, selected_c_flags, show_flags,
};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Export a destination CPU profile as compiler-specific build configurations"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Capture the destination machine's Archspec CPU description to portable JSON.
    Capture {
        #[arg(long)]
        target: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Define a destination CPU by model, without requiring the hardware.
    Model {
        #[arg(long)]
        target: String,
        #[arg(long)]
        cpu: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Render the selected CPU for the actual compiler used on the build host.
    Emit {
        #[arg(long, conflicts_with = "target")]
        profile: Option<PathBuf>,
        /// Target triple required when selecting native or a model directly.
        #[arg(long)]
        target: Option<String>,
        #[arg(long, value_enum)]
        format: OutputFormat,
        #[arg(long)]
        cpu: Option<String>,
        #[arg(long)]
        compiler: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "gcc")]
        c_compiler: CCompiler,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Cargo,
    Gcc,
    Clang,
    Cmake,
    Meson,
    CcRs,
}
#[derive(Clone, Copy, ValueEnum)]
enum CCompiler {
    Gcc,
    Clang,
}
impl CCompiler {
    const fn name(self) -> &'static str {
        match self {
            Self::Gcc => "gcc",
            Self::Clang => "clang",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Capture { target, output } => CpuTargetSelection::Native {
            target_triple: &target,
        }
        .resolve()?
        .write(&output),
        Command::Model {
            target,
            cpu,
            output,
        } => CpuTargetSelection::Model {
            target_triple: &target,
            cpu: &cpu,
        }
        .resolve()?
        .write(&output),
        Command::Emit {
            profile,
            target,
            format,
            cpu,
            compiler,
            c_compiler,
            output,
        } => {
            let saved = profile
                .as_deref()
                .map(DestinationProfile::read)
                .transpose()?;
            let (profile, selected_cpu) = if let Some(saved) = &saved {
                let selection = CpuTargetSelection::Profile(saved);
                let selected_cpu = cpu.as_deref().filter(|name| *name != "native");
                (selection.resolve()?, selected_cpu)
            } else {
                let target = target.as_deref().context("emit needs --profile or --target")?;
                let selection = match cpu.as_deref() {
                    None | Some("native") => CpuTargetSelection::Native { target_triple: target },
                    Some(cpu) => CpuTargetSelection::Model { target_triple: target, cpu },
                };
                (selection.resolve()?, None)
            };
            let cpu = selected_cpu;
            let rendered = match format {
                OutputFormat::Cargo => cargo_toml(
                    &profile,
                    cpu,
                    compiler.as_deref().unwrap_or_else(|| Path::new("rustc")),
                )?,
                OutputFormat::Gcc => show_flags(&selected_c_flags(
                    &profile,
                    cpu,
                    "gcc",
                    compiler.as_deref().unwrap_or_else(|| Path::new("gcc")),
                )?),
                OutputFormat::Clang => show_flags(&selected_c_flags(
                    &profile,
                    cpu,
                    "clang",
                    compiler.as_deref().unwrap_or_else(|| Path::new("clang")),
                )?),
                OutputFormat::Cmake | OutputFormat::Meson | OutputFormat::CcRs => {
                    let flags = selected_c_flags(
                        &profile,
                        cpu,
                        c_compiler.name(),
                        compiler
                            .as_deref()
                            .unwrap_or_else(|| Path::new(c_compiler.name())),
                    )?;
                    if matches!(format, OutputFormat::Cmake) {
                        cmake_toolchain(&flags)
                    } else if matches!(format, OutputFormat::Meson) {
                        meson_options(&flags)
                    } else {
                        cc_rs_flags_json(&flags)?
                    }
                }
            };
            if let Some(output) = output {
                std::fs::write(&output, rendered)
                    .with_context(|| format!("cannot write {}", output.display()))?;
            } else {
                print!("{rendered}");
            }
            Ok(())
        }
    }
}
