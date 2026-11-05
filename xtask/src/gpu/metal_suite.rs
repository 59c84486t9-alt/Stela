//! Differential testing of Stela's Metal stack against a real Mac.
//!
//! Every case is an assertion in this module's code: what Metal's
//! specification guarantees a program, to the precision a program could
//! notice. Where the specification allows a range (the last ulps of fast
//! math, a fused or separate multiply-add, the order atomics return in,
//! alpha-to-coverage dither) the case accepts all of it, so the driver may
//! take the fastest implementation; a result the specification leaves
//! undefined has no case. The Mac proves each assertion holds on Apple
//! hardware: `mac` runs the plan there and `check` holds its results to the
//! plan, and the same plan, runner and libraries then run in a Stela guest.
//!
//!     cargo xtask gpu metal-suite plan            write DIR/plan
//!     cargo xtask gpu metal-suite mac             run it on the Mac
//!     cargo xtask gpu metal-suite check RESULTS   hold a run to the plan
//!     cargo xtask gpu metal-suite serve           run it in a Stela guest
//!     cargo xtask gpu metal-suite compare REF RUN compare two runs
//!     cargo xtask gpu metal-suite offline         compile the AIR with Stela's compiler
//!     cargo xtask gpu metal-suite probe           which functions each MSL version compiles
//!     cargo xtask gpu metal-suite coverage        what macOS's shaders use that no case does
use crate::tools;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::{fs, path::PathBuf};

mod arguments;
mod blits;
mod check;
mod compute;
mod convert;
mod coverage;
mod features;
mod guest;
mod integer;
mod math;
mod plan;
mod reference;
mod remote;
mod render;
mod resources;
mod sequences;
mod stages;
mod textures;
mod values;

/// The runner, the MSL corpus and the probe's availability record.
fn assets() -> PathBuf {
    tools::root().join("crates/stela-driver-gpu/tests/metal_suite")
}

#[derive(Args, Clone)]
pub struct Selection {
    /// Working directory for the plan and results.
    #[arg(long, default_value = ".stela/metal-suite")]
    out: PathBuf,
    /// Only cases whose names contain this text (repeatable).
    #[arg(long)]
    only: Vec<String>,
}

impl Selection {
    fn out(&self) -> PathBuf {
        if self.out.is_absolute() {
            self.out.clone()
        } else {
            tools::root().join(&self.out)
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Write DIR/plan: plan.json, every input and the MSL sources.
    Plan {
        #[command(flatten)]
        selection: Selection,
    },
    /// Find which functions of each guarded corpus source Apple's compiler
    /// refuses at each MSL version, into availability.json.
    Probe {
        #[command(flatten)]
        selection: Selection,
        #[arg(long, default_value = remote::HOST)]
        host: String,
    },
    /// Build the libraries and the runner on the Mac, run every case there
    /// and bring back the AIR, metallibs, runner and DIR/results/mac.
    Mac {
        #[command(flatten)]
        selection: Selection,
        #[arg(long, default_value = remote::HOST)]
        host: String,
    },
    /// Hold a run's outputs to the expectations the plan states.
    Check {
        #[command(flatten)]
        selection: Selection,
        /// The results directory (DIR/results/mac by default).
        results: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Compare a run against a reference run within each output's tolerance,
    /// and report the cases that ran much slower.
    Compare {
        #[command(flatten)]
        selection: Selection,
        reference: PathBuf,
        test: PathBuf,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Serve DIR/plan to a Stela guest over its network and receive its
    /// results into DIR/results; prints the guest's commands.
    Serve {
        #[command(flatten)]
        selection: Selection,
        #[arg(long, default_value_t = 8765)]
        port: u16,
    },
    /// Compile each case's functions from the Mac's AIR with Stela's compiler
    /// (the stela_metal_corpus tool), recording acceptance and NIR.
    Offline {
        #[command(flatten)]
        selection: Selection,
        #[arg(long)]
        compiler: PathBuf,
    },
    /// Rank the AIR intrinsic families macOS's own shaders call that the
    /// suite's libraries (DIR/plan/lib, from `mac`) never call.
    Coverage {
        #[command(flatten)]
        selection: Selection,
        #[arg(long, default_value = remote::HOST)]
        host: String,
        /// Copy the system metallibs from the Mac again.
        #[arg(long)]
        refresh: bool,
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Plan { selection } => write_plan(&selection).map(drop),
        Command::Probe { selection, host } => remote::probe(&selection.out(), &host),
        Command::Mac { selection, host } => {
            let plan = write_plan(&selection)?;
            remote::mac(&selection.out(), &plan, &host)
        }
        Command::Check {
            selection,
            results,
            report,
        } => {
            let out = selection.out();
            let results = results.unwrap_or_else(|| out.join("results/mac"));
            check::run(&out, None, &results, &selection.only, report.as_deref())
        }
        Command::Compare {
            selection,
            reference,
            test,
            report,
        } => check::run(
            &selection.out(),
            Some(&reference),
            &test,
            &selection.only,
            report.as_deref(),
        ),
        Command::Serve { selection, port } => guest::serve(&selection.out(), port, &selection.only),
        Command::Offline {
            selection,
            compiler,
        } => remote::offline(&selection.out(), &compiler, &selection.only),
        Command::Coverage {
            selection,
            host,
            refresh,
            report,
        } => coverage::run(&selection.out(), &host, refresh, report.as_deref()),
    }
}

/// Every family of cases.
fn build(plan: &mut plan::Plan) {
    math::build(plan);
    integer::build(plan);
    convert::build(plan);
    compute::build(plan);
    features::build(plan);
    textures::build(plan);
    render::build(plan);
    arguments::build(plan);
    blits::build(plan);
    sequences::build(plan);
    stages::build(plan);
    resources::build(plan);
}

fn availability() -> Result<plan::Availability> {
    let path = assets().join("availability.json");
    let text = fs::read_to_string(&path).with_context(|| path.display().to_string())?;
    let record: serde_json::Value = serde_json::from_str(&text)?;
    Ok(serde_json::from_value(record["sources"].clone())?)
}

fn full_plan() -> Result<plan::Plan> {
    let mut plan = plan::Plan::new(availability()?);
    build(&mut plan);
    Ok(plan)
}

fn write_plan(selection: &Selection) -> Result<serde_json::Value> {
    let dir = selection.out().join("plan");
    fs::create_dir_all(&dir)?;
    let written = full_plan()?.write(&dir, &assets().join("corpus"), &selection.only)?;
    let cases = written["cases"].as_array().map_or(0, Vec::len);
    if cases == 0 {
        bail!("no case matches {:?}", selection.only);
    }
    println!(
        "{cases} cases, {} libraries in {}",
        written["builds"].as_object().map_or(0, |b| b.len()),
        dir.display()
    );
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The plan builds without the Mac: every case is unique, names the
    /// libraries it uses and states at least one assertion unless it is
    /// informational or compared between runs only.
    #[test]
    fn plan_builds() {
        let plan = full_plan().unwrap();
        let mut names = HashSet::new();
        for case in plan.cases() {
            let name = plan::name_of(case);
            assert!(names.insert(name.to_string()), "{name}");
            if let Some(library) = case["library"].as_str() {
                assert!(plan.libraries().contains_key(library), "{name}: {library}");
            }
        }
        assert!(names.len() > 1000, "{}", names.len());
    }

    #[test]
    fn selection_paths_resolve_under_the_root() {
        let s = Selection {
            out: ".stela/metal-suite".into(),
            only: vec![],
        };
        assert!(s.out().starts_with(tools::root()));
    }
}
