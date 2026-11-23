use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use cpu_target_profile::{
    DestinationProfile, cargo_toml, cmake_toolchain, meson_options, selected_c_flags, show_flags,
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
        #[arg(long)]
        profile: PathBuf,
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
        Command::Capture { target, output } => DestinationProfile::capture(&target)?.write(&output),
        Command::Model {
            target,
            cpu,
            output,
        } => DestinationProfile::named(&target, &cpu)?.write(&output),
        Command::Emit {
            profile,
            format,
            cpu,
            compiler,
            c_compiler,
            output,
        } => {
            let profile = DestinationProfile::read(&profile)?;
            let cpu = cpu.as_deref();
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
                OutputFormat::Cmake | OutputFormat::Meson => {
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
                    } else {
                        meson_options(&flags)
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
