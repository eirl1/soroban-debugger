use clap::{Parser, Subcommand};
use soroban_debugger::benchmarks::{
    collect_criterion_baseline, compare_baselines, emit_github_annotations, load_baseline_json,
    overall_status, render_markdown_report, write_baseline_json, ComparisonConfig,
    CriterionBaseline, RegressionStatus,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "bench-regression")]
#[command(about = "Record and compare Criterion benchmark baselines for CI regression gating")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record a baseline JSON from a Criterion `target/criterion` directory
    Record {
        /// Path to Criterion output directory (default: target/criterion)
        #[arg(long, default_value = "target/criterion")]
        criterion: PathBuf,
        /// Output path for baseline JSON
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare current benchmark results against a baseline
    Compare {
        /// Baseline JSON file created by `record`
        #[arg(long)]
        baseline: PathBuf,
        /// Current JSON file (if omitted, scans `--criterion`)
        #[arg(long)]
        current: Option<PathBuf>,
        /// Path to Criterion output directory (used when --current is not provided)
        #[arg(long, default_value = "target/criterion")]
        criterion: PathBuf,
        /// Warn threshold percent
        #[arg(long, default_value_t = 10.0)]
        warn_pct: f64,
        /// Fail threshold percent
        #[arg(long, default_value_t = 20.0)]
        fail_pct: f64,
        /// Maximum rows in the markdown table
        #[arg(long, default_value_t = 50)]
        max_rows: usize,
        /// Emit GitHub Actions annotations (warning/error) for the top N regressions
        #[arg(long, default_value_t = 20)]
        annotate_top: usize,
        /// Output current baseline JSON to this path (useful for caching/artifacts)
        #[arg(long)]
        out_current: Option<PathBuf>,
        /// Exit non-zero when baseline is missing/unreadable
        #[arg(long, default_value_t = true)]
        require_baseline: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> soroban_debugger::Result<()> {
    match cli.command {
        Commands::Record { criterion, out } => {
            let baseline = collect_criterion_baseline(criterion)?;
            write_baseline_json(out, &baseline)?;
        }
        Commands::Compare {
            baseline,
            current,
            criterion,
            warn_pct,
            fail_pct,
            max_rows,
            annotate_top,
            out_current,
            require_baseline,
        } => {
            let baseline_data = match load_baseline_json(&baseline) {
                Ok(b) => b,
                Err(e) => {
                    if require_baseline {
                        return Err(e);
                    }
                    println!("::warning::Benchmark baseline missing; skipping regression gate.");
                    return Ok(());
                }
            };

            let current_data: CriterionBaseline = match current {
                Some(path) => load_baseline_json(path)?,
                None => collect_criterion_baseline(criterion)?,
            };

            if let Some(path) = out_current {
                write_baseline_json(path, &current_data)?;
            }

            let config = ComparisonConfig { warn_pct, fail_pct };
            let deltas = compare_baselines(&baseline_data, &current_data, config);
            emit_github_annotations(&deltas, annotate_top);

            let report = render_markdown_report(&deltas, config, max_rows);
            println!("{report}");

            match overall_status(&deltas) {
                RegressionStatus::Fail => std::process::exit(1),
                RegressionStatus::Warn | RegressionStatus::Pass => {}
            }
        }
    }

    Ok(())
}
