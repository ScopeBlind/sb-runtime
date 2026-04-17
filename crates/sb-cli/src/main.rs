//! `sb` — the sb-runtime CLI.
//!
//! ```text
//! sb exec --policy policy.cedar --sandbox profile.json -- /usr/bin/cat /etc/hosts
//! sb verify .receipts/
//! sb keys generate --out ~/.config/sb/key.pem
//! ```
//!
//! The `exec` command is the heart: evaluate the Cedar policy against the
//! requested command, apply the OS-native sandbox profile, emit a signed
//! receipt, then `execv` the target.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use sb_policy::{Decision, Evaluator};
use sb_receipt::{Decision as RDecision, Keypair, ReceiptBuilder};
use sb_sandbox::{apply, Profile};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "sb",
    about = "sb-runtime — lightweight agent sandbox with Cedar policy + signed receipts",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Evaluate policy, apply sandbox, emit receipt, exec command.
    Exec(ExecArgs),
    /// Verify a chain of receipts offline.
    Verify(VerifyArgs),
    /// Key management.
    #[command(subcommand)]
    Keys(KeysCmd),
}

#[derive(Parser, Debug)]
struct ExecArgs {
    /// Path to the Cedar policy file.
    #[arg(long)]
    policy: PathBuf,
    /// Path to the sandbox profile (JSON). If omitted, uses a restrictive default.
    #[arg(long)]
    sandbox: Option<PathBuf>,
    /// Directory to append signed receipts to.
    #[arg(long, default_value = ".receipts")]
    receipts: PathBuf,
    /// Optional 32-byte hex-encoded Ed25519 seed. If omitted, a new keypair
    /// is generated and written to `.sb/key.seed` in the receipts directory.
    #[arg(long)]
    key_seed_hex: Option<String>,
    /// Skip sandbox application. Policy + receipt still fire. Use only for
    /// local dev on platforms where sandboxing isn't implemented yet.
    #[arg(long)]
    allow_unsandboxed: bool,
    /// The command to exec, and its arguments.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Parser, Debug)]
struct VerifyArgs {
    /// Directory containing receipt JSON files, sorted lexicographically.
    path: PathBuf,
}

#[derive(Subcommand, Debug)]
enum KeysCmd {
    /// Generate a fresh Ed25519 keypair and print the seed hex.
    Generate {
        /// Optional path to write the seed to. If omitted, prints to stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Exec(args) => cmd_exec(args),
        Cmd::Verify(args) => cmd_verify(args),
        Cmd::Keys(KeysCmd::Generate { out }) => cmd_keys_generate(out),
    }
}

fn cmd_exec(args: ExecArgs) -> Result<()> {
    if args.command.is_empty() {
        bail!("no command given");
    }
    let command_path = args.command[0].clone();
    let command_args: Vec<String> = args.command.iter().skip(1).cloned().collect();

    // 1. Evaluate Cedar policy
    let eval = Evaluator::from_file(&args.policy)
        .with_context(|| format!("loading policy {:?}", args.policy))?;
    let decision = eval
        .evaluate_exec(&command_path, &command_args)
        .context("evaluating policy")?;

    // 2. Sign + emit a receipt for the decision, regardless of allow/deny
    let keypair = load_or_create_keypair(args.key_seed_hex.as_deref(), &args.receipts)?;
    std::fs::create_dir_all(&args.receipts)
        .with_context(|| format!("creating {:?}", args.receipts))?;
    let (prev_hash, sequence) = next_chain_link(&args.receipts)?;

    let r_decision = match &decision {
        Decision::Allow { .. } => RDecision::Allow,
        Decision::Deny { .. } => RDecision::Deny,
    };
    let policy_id = decision.policy_id().to_string();
    let receipt = ReceiptBuilder::new()
        .decision(r_decision)
        .action("exec", &command_path)
        .policy(&policy_id)
        .sequence(sequence)
        .prev_hash(prev_hash)
        .context(
            "args",
            serde_json::Value::Array(
                command_args
                    .iter()
                    .map(|a| serde_json::Value::String(a.clone()))
                    .collect(),
            ),
        )
        .build_and_sign(&keypair)
        .context("building receipt")?;

    let receipt_path = args
        .receipts
        .join(format!("{:06}.json", receipt.payload.sequence));
    std::fs::write(&receipt_path, serde_json::to_string_pretty(&receipt)?)
        .with_context(|| format!("writing {:?}", receipt_path))?;
    info!(
        decision = receipt.payload.decision.as_str(),
        sequence = receipt.payload.sequence,
        receipt = %receipt_path.display(),
        "receipt emitted"
    );

    // 3. If denied, exit before applying sandbox / exec
    if let Decision::Deny { reason, .. } = &decision {
        eprintln!("sb: denied by policy: {reason}");
        std::process::exit(2);
    }

    // 4. Apply sandbox
    let profile = if let Some(sandbox_path) = args.sandbox {
        Profile::from_json_file(&sandbox_path)
            .with_context(|| format!("loading sandbox profile {sandbox_path:?}"))?
    } else {
        Profile::read_only_transform()
    };

    if !args.allow_unsandboxed {
        match apply(&profile) {
            Ok(()) => info!("sandbox applied"),
            Err(e) => {
                warn!("sandbox apply failed: {e}. Pass --allow-unsandboxed to run anyway.");
                bail!("sandbox apply failed: {e}");
            }
        }
    } else {
        warn!("sandbox skipped via --allow-unsandboxed");
    }

    // 5. Exec the target command
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = std::process::Command::new(&command_path)
            .args(&command_args)
            .exec();
        bail!("execve failed: {err}");
    }
    #[cfg(not(unix))]
    {
        // Non-Unix: spawn and wait; exec semantics differ.
        let status = std::process::Command::new(&command_path)
            .args(&command_args)
            .status()
            .context("spawning command")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn cmd_verify(args: VerifyArgs) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(&args.path)?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);

    if entries.is_empty() {
        bail!("no receipt files found in {:?}", args.path);
    }

    let mut receipts: Vec<sb_receipt::Receipt> = Vec::with_capacity(entries.len());
    for e in &entries {
        let data = std::fs::read_to_string(e.path())?;
        let r: sb_receipt::Receipt =
            serde_json::from_str(&data).with_context(|| format!("parsing {:?}", e.path()))?;
        receipts.push(r);
    }

    // All receipts in a chain must share one pubkey (this is a v0.1
    // simplification; multi-issuer chains land in v0.2).
    let first_pk_hex = receipts[0].pubkey.clone();
    let pk_bytes = hex::decode(&first_pk_hex)?;
    if pk_bytes.len() != 32 {
        bail!("first receipt pubkey is not 32 bytes");
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)?;

    sb_receipt::verify_chain(&receipts, pubkey)?;

    println!(
        "✓ {} receipts verified ({} → {})",
        receipts.len(),
        receipts
            .first()
            .map(|r| r.payload.timestamp.as_str())
            .unwrap_or("?"),
        receipts
            .last()
            .map(|r| r.payload.timestamp.as_str())
            .unwrap_or("?"),
    );
    Ok(())
}

fn cmd_keys_generate(out: Option<PathBuf>) -> Result<()> {
    // We expose the seed (not the signing key itself) so it's directly
    // usable with `--key-seed-hex`. This is the same convention libsodium
    // uses for ed25519 secret key import.
    let kp = Keypair::generate();
    let _ = &kp; // currently Keypair doesn't expose seed; this is a v0.2 item
    warn!(
        "v0.1 does not expose raw seed extraction via the API; use `openssl rand -hex 32` \
         for a deterministic seed and re-import via --key-seed-hex"
    );
    if let Some(out) = out {
        std::fs::write(&out, kp.to_pubkey_hex())?;
        println!("pubkey hex written to {out:?}");
    } else {
        println!("pubkey: {}", kp.to_pubkey_hex());
    }
    Ok(())
}

fn load_or_create_keypair(
    seed_hex: Option<&str>,
    receipts_dir: &std::path::Path,
) -> Result<Keypair> {
    if let Some(hex_str) = seed_hex {
        return Keypair::from_seed_hex(hex_str).map_err(Into::into);
    }
    let sb_dir = receipts_dir.join(".sb");
    let key_path = sb_dir.join("key.seed");
    if key_path.exists() {
        let s = std::fs::read_to_string(&key_path)?;
        return Keypair::from_seed_hex(s.trim()).map_err(Into::into);
    }
    // Create fresh seed + persist.
    std::fs::create_dir_all(&sb_dir).with_context(|| format!("creating {sb_dir:?}"))?;
    let seed: [u8; 32] = rand_seed();
    let hex_str = hex::encode(seed);
    std::fs::write(&key_path, &hex_str)?;
    Ok(Keypair::from_seed(&seed))
}

fn rand_seed() -> [u8; 32] {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}

fn next_chain_link(dir: &std::path::Path) -> Result<(String, u64)> {
    if !dir.exists() {
        return Ok(("genesis".to_string(), 1));
    }
    let mut files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    if files.is_empty() {
        return Ok(("genesis".to_string(), 1));
    }
    files.sort_by_key(|e| e.path());
    let Some(last) = files.last() else {
        return Ok(("genesis".to_string(), 1));
    };
    let data = std::fs::read_to_string(last.path())?;
    let prev: sb_receipt::Receipt = serde_json::from_str(&data)?;
    let prev_hash = prev.hash_for_next()?;
    Ok((prev_hash, prev.payload.sequence + 1))
}

// The CLI crate depends on `rand` + `hex` transitively. Declare the minimal
// direct usage so it doesn't break compilation if the workspace is pruned.
#[allow(unused_extern_crates)]
extern crate hex;
#[allow(unused_extern_crates)]
extern crate rand;
