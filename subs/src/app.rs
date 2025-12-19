use libveritas::sname::{NameLike, SName};
use std::{fs, io};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use atty::Stream;
use base64::Engine;
use clap::{Parser, Subcommand};

use libveritas_methods::{STEP_ELF, STEP_ID, FOLD_ELF, FOLD_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Prover, ProverOpts, Receipt};

use serde::{Deserialize, Serialize};

use spacedb::db::Database;
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spacedb::tx::{ProofType};
use bitcoin::{key, OutPoint, ScriptBuf, XOnlyPublicKey};
use bitcoin::hashes::{Hash as HashUtil, sha256};
use bitcoin::secp256k1::{rand, Secp256k1};
use libveritas::cert::{Certificate, HandleSubtree, LeafKind, PtrsSubtree, SpacesSubtree, Witness};
use spaces_protocol::slabel::SLabel;


use libveritas_zk::BatchReader;
use libveritas_zk::guest::Commitment;
use regex::Regex;
use spacedb::subtree::SubTree;
use spaces_client::auth::http_client_with_auth;
use spaces_client::jsonrpsee::http_client::HttpClient;
use spaces_client::rpc::RpcClient;
use spaces_ptr::sptr::Sptr;
use crate::{Batch, BatchEntry, HandleRequest};

const STAGING_FILE: &str = "uncommitted.json";

#[derive(Parser)]
#[command(
    bin_name = "subs",
    author,
    version,
    about,
    before_help = r#"


      ✦     @
   ✦     ₿     ✦      subs — create, prove & verify Bitcoin handles off-chain
      ✦     @"#)]
pub struct Cli {
    /// Working directory (default: current dir)
    #[arg(short = 'C', global = true)]
    pub c: Option<String>,

    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Request a handle e.g. alice@example (for end-users)
    #[command(name = "request")]
    Request(RequestArgs),

    /// Operators: Stage an inclusion request for the next batch
    #[command(name = "add")]
    Add(AddArgs),

    /// Operators: Commit the next batch
    #[command(name = "commit")]
    Commit(CommitArgs),

    /// Operators: zk-STARK prove the commitments (GPU recommended)
    #[command(name = "prove")]
    Prove(ProveArgs),

    /// Operators: Compress the root certificate with STARK → SNARK conversion.
    #[command(name = "compress")]
    Compress(CompressArgs),

    /// Operators: Status of current batch
    #[command(name = "status")]
    Status,

    /// Certificate operations (issue, verify, …)
    #[command(name = "cert", subcommand)]
    Cert(CertCmd),
}

#[derive(Subcommand)]
pub enum CertCmd {
    /// Operators: issue a handle certificate
    Issue(IssueArgs),

    /// Verify a handle certificate against a root certificate
    Verify(VerifyArgs),
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct RequestArgs {
    /// The handle name e.g. alice@example
    handle: SName,
    #[arg(short = 's', long)]
    script_pubkey: Option<String>,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct AddArgs {
    pub(crate) files: Vec<String>,
}

#[derive(clap::Args, Clone)]
#[command(author, version, about, long_about = None)]
pub struct CommitArgs {
    #[arg(long, short)]
    dry_run: bool,
}

#[derive(clap::Args, Clone)]
#[command(author, version, about, long_about = None)]
pub struct CompressArgs {
    #[arg(long, short)]
    dry_run: bool,
}

#[derive(clap::Args, Clone)]
#[command(author, version, about, long_about = None)]
pub struct ProveArgs {
    #[arg(long, short)]
    dry_run: bool,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct IssueArgs {
    /// The handle name e.g. alice@example
    pub handle: SName,
    /// Spaces rpc url
    #[arg(long)]
    pub rpc_url: String,
    /// Spaces rpc user
    #[arg(long)]
    pub rpc_user: Option<String>,
    /// Spaces rpc password
    #[arg(long)]
    pub rpc_password: Option<String>,
    /// Space cookie path
    #[arg(long)]
    pub rpc_cookie: Option<String>,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct VerifyArgs {
    /// The handle certificate file
    pub cert_file: PathBuf,

    /// The root certificate file (--root <FILE>)
    #[arg(long)]
    root: Option<PathBuf>,

    #[arg(required = true)]
    pub rpc_url: String,
    /// Spaces rpc user
    #[arg(long)]
    pub rpc_user: Option<String>,
    /// Spaces rpc password
    #[arg(long)]
    pub rpc_password: Option<String>,
    /// Space cookie path
    #[arg(long)]
    pub rpc_cookie: Option<String>,
}

#[derive(Default, Serialize, Deserialize, Clone)]
struct Chain {
    version: u32,
    space: Option<SLabel>,
    entries: Vec<ChainEntry>,
    tip_receipt: Option<String>,
    tip_receipt_groth16: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ChainEntry {
    pre_diff_root: Option<String>,
    post_diff_root: String,
    diff_file: String,
    subtree_file: Option<String>,
    step_receipt: Option<String>,
    aggregate_receipt: Option<String>,
    aggregate_groth16: Option<String>,
}

pub struct App {
    wd: PathBuf,
}

impl App {
    pub fn new(c: &Option<String>) -> anyhow::Result<Self> {
        let mut wd = PathBuf::new();
        if let Some(dir) = c {
            wd.push(dir);
            if !wd.exists() {
                fs::create_dir_all(&wd)?;
            }
            let md = fs::metadata(&wd)?;
            if !md.is_dir() {
                return Err(anyhow!("Path is not a directory: {}", wd.display()));
            }
        } else {
            wd.push(".");
        }
        Ok(Self { wd })
    }

    fn staging_path(&self) -> PathBuf {
        self.wd.join(STAGING_FILE)
    }

    fn commitments_dir(&self) -> PathBuf {
        self.wd.join("commitments")
    }

    fn chain_path(&self) -> PathBuf {
        self.wd.join("chain.json")
    }

    fn sdb_path(&self, space: &SLabel) -> PathBuf {
        self.wd.join(format!("{}.sdb", space))
    }

    fn step_path_for(&self, idx: usize, post_diff_root: &str) -> PathBuf {
        let base = format!("{:06}_{}", idx, post_diff_root);
        self.commitments_dir().join(format!("{}.step.zk.bin", base))
    }

    fn fold_path_for(&self, idx: usize, post_diff_root: &str) -> PathBuf {
        let base = format!("{:06}_{}", idx, post_diff_root);
        self.commitments_dir().join(format!("{}.fold.zk.bin", base))
    }

    fn load_chain(&self) -> anyhow::Result<Chain> {
        let p = self.chain_path();
        if p.exists() { Ok(serde_json::from_slice(&fs::read(p)?)?) } else { Ok(Chain::default()) }
    }

    fn save_chain(&self, chain: &Chain) -> anyhow::Result<()> {
        fs::create_dir_all(self.commitments_dir())?;
        fs::write(self.chain_path(), serde_json::to_vec_pretty(chain)?)?;
        Ok(())
    }

    fn load_batch(&self) -> anyhow::Result<Option<Batch>> {
        let p = self.staging_path();
        if !p.exists() { return Ok(None); }
        let raw = fs::read(p)?;
        let batch = serde_json::from_slice(raw.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "could not parse uncommitted.json"))?;
        Ok(Some(batch))
    }

    fn save_batch(&self, batch: &Batch) -> anyhow::Result<()> {
        let s = serde_json::to_string_pretty(batch)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "unable to serialize batch"))?;
        fs::write(self.staging_path(), s)?;
        Ok(())
    }

    fn load_receipt_and_commitment(&self, path: &Path) -> anyhow::Result<(Receipt, Commitment)> {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let receipt: Receipt = borsh::from_slice(&bytes)
            .map_err(|e| anyhow!("decode receipt {}: {}", path.display(), e))?;
        let cm: Commitment = receipt.journal.decode()
            .map_err(|e| anyhow!("decode journal {}: {}", path.display(), e))?;
        Ok((receipt, cm))
    }

    pub fn cmd_status(&self) -> anyhow::Result<()> {
        let batch = self.load_batch()?;
        if let Some(batch) = batch {
            println!("✔ Pending changes");
            println!("   → Space        : {}", batch.space);
            println!("   → New handles: {}", batch.entries.len());
            println!("\nRun `subs commit` to commit changes.");
        } else {
            println!("\nNo changes to commit.");
            println!("   → Use `subs add` to stage handle requests.");
        }
        Ok(())
    }

    pub fn cmd_add(&self, args: AddArgs) -> anyhow::Result<()> {
        let requests = args.expand_files()?;

        let mut batch: Option<Batch> = self.load_batch()?;
        let chain = self.load_chain()?;
        let db = if let Some(space) = &chain.space {
            self.load_db(space)?
        } else { None };
        let mut reader = if let Some(db) = db {
            Some(db.begin_read()?)
        } else { None };
        let mut get_handle = |handle: &SName| -> anyhow::Result<Option<Vec<u8>>> {
            match reader.as_mut() {
                None => Ok(None),
                Some(r) => Ok(r.get(&Sha256Hasher::hash(handle.subspace().expect("subspace").as_slabel().as_ref()))?)
            }
        };

        let batch_initial = batch.as_ref()
            .map(|b| b.entries.len()).unwrap_or(0);
        let mut add_req = |req: HandleRequest, batch: &mut Option<Batch>| -> anyhow::Result<()> {
            let existing = chain.space.as_ref()
                .or(batch.as_ref().map(|s| &s.space));
            if let Some(existing) = existing {
                // TODO: fix clone
                if Some(existing.clone()) != req.handle.space() {
                    return Err(anyhow!("Cannot add '{}' to existing space '{}'",
                         req.handle, existing)
                    );
                }
            }

            let script_pubkey = hex::decode(&req.script_pubkey)
                .map_err(|e| anyhow!("Invalid script_pubkey hex: {}", e))?;


            let prev = get_handle(&req.handle)?
                .or_else(|| batch.as_ref()
                    .and_then(|b| b.entries.iter()
                        .find(|e| req.handle.subspace().as_ref() == Some(&e.sub_label))
                        .map(|e| e.script_pubkey.to_bytes())));

            if let Some(value) = prev {
                if value != script_pubkey {
                    println!("   → {} - skipping already exists with a different spk", req.handle);
                }

                // Otherwise just ignore it its already there same value
                return Ok(());
            }

            let mut b = batch.take().unwrap_or_else(|| Batch::new(req.handle.space().expect("space").clone()));
            b.entries.push(BatchEntry { sub_label: req.handle.subspace().expect("subspace").clone(), script_pubkey: script_pubkey.into() });
            *batch = Some(b);
            println!("   → {}", req.handle);
            Ok(())
        };

        for file in &requests {
            let raw = fs::read(file)?;
            let req: HandleRequest = serde_json::from_slice(&raw)
                .map_err(|e| anyhow!("Could not parse {}: {}", file.display(), e))?;
            add_req(req, &mut batch)?;
        }

        if args.files.is_empty() && !atty::is(Stream::Stdin) {
            let mut raw = Vec::new();
            io::stdin().read_to_end(&mut raw)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Nothing to add"))?;
            let req: HandleRequest = serde_json::from_slice(&raw)
                .map_err(|e| anyhow!("Could not parse stdin: {}", e))?;
            add_req(req, &mut batch)?;
        }


        if let Some(b) = &batch {
            let chain = self.load_chain()?;
            if let Some(space) = &chain.space {
                if &b.space != space {
                    return Err(
                        anyhow!("Batch space {} doesn't match existing space {} in current working directory",
                        b.space, space
                    ));
                }
            }


            self.save_batch(b)?;
            println!("✔ Added {} request(s) to batch", b.entries.len() - batch_initial);
        }


        Ok(())
    }

    fn load_db(&self, space: &SLabel) -> anyhow::Result<Option<Database<Sha256Hasher>>> {
        let db_path = self.sdb_path(&space);
        if !db_path.exists() {
            return Ok(None);
        }
        let db = Database::open(db_path.to_str().unwrap())?;
        Ok(Some(db))
    }

    fn load_or_create_db(&self, space: &SLabel) -> anyhow::Result<Database<Sha256Hasher>> {
        let db_path = self.sdb_path(&space);
        Ok(Database::open(db_path.to_str().unwrap())?)
    }

    fn prepare_zk_input(&self) -> anyhow::Result<(Option<Vec<u8>>, Batch)> {
        let batch = self.load_batch()?.ok_or_else(|| anyhow!("No uncommitted changes found"))?;
        let new_batch = batch.to_zk_input();
        let db = match self.load_db(&batch.space)? {
            None => return Ok((None, batch)),
            Some(db) => db,
        };

        let reader = BatchReader(new_batch.as_slice());
        let keys = reader.iter().map(|t| t.handle.try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid subspace hash")))
            .collect::<Result<Vec<Hash>, io::Error>>()?;
        let mut snapshot = db.begin_read()?;
        let subtree = snapshot.prove(&keys, ProofType::Standard)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("could not generate subtree: {}", e)))?;
        let subtree = borsh::to_vec(&subtree)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("could not encode subtree: {}", e)))?;

        Ok((Some(subtree), batch))
    }

    pub fn cmd_commit(&self, args: CommitArgs) -> anyhow::Result<()> {
        if !self.staging_path().exists() { return Err(anyhow!("No changes to commit")); }

        let (subtree_opt, batch) = self.prepare_zk_input()?;
        let diff_bytes = batch.to_zk_input();

        let chain = match subtree_opt {
            Some(subtree_bytes) => {
                let c = libveritas_zk::guest::run(subtree_bytes.clone(), diff_bytes.clone(), STEP_ID, FOLD_ID)
                    .map_err(|e| anyhow!("could not validate program input: {}", e))?;

                if args.dry_run {
                    println!("\nPreview:");
                    println!("   → pre_root : {}", hex::encode(&c.initial_root));
                    println!("   → post_root: {}", hex::encode(&c.final_root));
                    return Ok(());
                }

                fs::create_dir_all(self.commitments_dir())?;
                let mut chain = self.load_chain()?;
                if chain.space.is_none() { chain.space = Some(batch.space.clone()); }

                let pre_hex = hex::encode(&c.initial_root);
                let post_hex = hex::encode(&c.final_root);
                let idx = chain.entries.len();
                let base = format!("{:06}_{}", idx, post_hex);
                let diff_rel = format!("{}.diff.bin", base);
                let subtree_rel = format!("{}.subtree.bin", base);

                fs::write(self.commitments_dir().join(&diff_rel), &diff_bytes)?;
                fs::write(self.commitments_dir().join(&subtree_rel), subtree_bytes)?;

                chain.entries.push(ChainEntry {
                    pre_diff_root: Some(pre_hex),
                    post_diff_root: post_hex,
                    diff_file: diff_rel,
                    subtree_file: Some(subtree_rel),
                    step_receipt: None,
                    aggregate_receipt: None,
                    aggregate_groth16: None,
                });
                self.save_chain(&chain)?;

                let db = self.load_db(&batch.space)?
                    .ok_or(anyhow!("No database found"))?;
                let mut tx = db.begin_write()?;
                for e in batch.entries {
                    tx = tx.insert(Sha256Hasher::hash(e.sub_label.as_slabel().as_ref()), e.script_pubkey.to_bytes())?;
                }
                tx.commit()?;
                chain
            }

            None => {
                if args.dry_run {
                    println!("initial commit: no subtree, skipping zk; no writes performed");
                    return Ok(());
                }

                let db = self.load_or_create_db(&batch.space)?;

                let mut tx = db.begin_write()?;
                for e in &batch.entries {
                    tx = tx.insert(Sha256Hasher::hash(e.sub_label.as_slabel().as_ref()), e.script_pubkey.to_bytes())?;
                }
                tx.commit()?;

                let end_root = hex::encode(
                    db.begin_read().expect("read").compute_root().expect("root")
                );

                fs::create_dir_all(self.commitments_dir())?;
                let mut chain = self.load_chain()?;
                if chain.space.is_none() { chain.space = Some(batch.space.clone()); }

                let idx = chain.entries.len();
                let base = format!("{:06}_{}", idx, end_root);
                let diff_rel = format!("{}.diff.bin", base);

                fs::write(self.commitments_dir().join(&diff_rel), &diff_bytes)?;

                chain.entries.push(ChainEntry {
                    pre_diff_root: None,
                    post_diff_root: end_root,
                    diff_file: diff_rel,
                    subtree_file: None,
                    step_receipt: None,
                    aggregate_receipt: None,
                    aggregate_groth16: None,
                });
                self.save_chain(&chain)?;
                chain
            }
        };

        println!("✔ Committed batch");
        println!("   → Tree root: {}", chain.entries.last().expect("last root").post_diff_root);

        fs::remove_file(self.staging_path())?;
        Ok(())
    }

    pub fn cmd_prove(&self, _args: ProveArgs) -> anyhow::Result<()> {
        let chain_path = self.chain_path();
        if !chain_path.exists() { return Err(anyhow!("missing {}", chain_path.display())); }
        let mut chain = self.load_chain().with_context(|| format!("loading {}", chain_path.display()))?;
        if chain.space.is_none() { return Err(anyhow!("No space to prove")); }

        println!("== Proving steps for space: {} ==", chain.space.as_ref().expect("space"));
        let store_dir = self.commitments_dir();

        for (i, entry) in chain.entries.iter_mut().skip(1).enumerate() {
            let step_path = self.step_path_for(i, &entry.post_diff_root);

            if step_path.exists() {
                if entry.step_receipt.is_none() {
                    entry.step_receipt = Some(step_path.file_name().unwrap().to_string_lossy().into());
                }
                println!("[#{}] step exists, skipping: {}", i, step_path.display());
                continue;
            }

            let diff_path = store_dir.join(&entry.diff_file);
            let subtree_rel = entry.subtree_file.as_ref()
                .ok_or_else(|| anyhow!("[#{}] missing subtree_file in chain.json", i))?;
            let subtree_path = store_dir.join(subtree_rel);

            let diff_bytes = fs::read(&diff_path)
                .with_context(|| format!("[#{}] reading diff {}", i, diff_path.display()))?;
            let subtree = fs::read(&subtree_path)
                .with_context(|| format!("[#{}] reading subtree {}", i, subtree_path.display()))?;

            let env = ExecutorEnv::builder()
                .write(&(subtree, diff_bytes, STEP_ID, FOLD_ID))
                .map_err(|e| anyhow!("[#{}] env write: {}", i, e))?
                .build()
                .map_err(|e| anyhow!("[#{}] env build: {}", i, e))?;

            let opts = ProverOpts::succinct();
            let prover = default_prover();
            println!("[#{}] Proving step {} → {}", i, entry.pre_diff_root.as_deref().unwrap_or("-"), entry.post_diff_root);
            let start = std::time::Instant::now();

            let prove_info = prover.prove_with_opts(env, STEP_ELF, &opts)
                .map_err(|e| anyhow!("[#{}] prove step failed: {}", i, e))?;
            let receipt = prove_info.receipt;

            receipt.verify(STEP_ID)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("[#{}] verify step failed: {}", i, e)))?;
            println!("[#{}] Step verified in {:?}", i, start.elapsed());

            let raw = borsh::to_vec(&receipt)
                .map_err(|e| anyhow!("[#{}] serialize step receipt: {}", i, e))?;
            fs::write(&step_path, raw)
                .with_context(|| format!("[#{}] writing {}", i, step_path.display()))?;

            entry.step_receipt = Some(step_path.file_name().unwrap().to_string_lossy().into());
        }

        self.save_chain(&chain)?;
        println!("Step pass complete.");
        self.fold_aggregate()?;
        Ok(())
    }

    fn fold_aggregate(&self) -> anyhow::Result<()> {
        let chain_path = self.chain_path();
        if !chain_path.exists() { return Err(anyhow!("missing {}", chain_path.display())); }
        let mut chain = self.load_chain().with_context(|| format!("loading {}", chain_path.display()))?;
        if chain.space.is_none() { return Err(anyhow!("No space to prove")); };
        println!("== Folding aggregate for space: {} ==", chain.space.as_ref().expect("space"));

        let mut acc_receipt: Option<Receipt> = None;
        let mut acc_commit: Option<Commitment> = None;
        let mut last_step_rel: Option<String> = None;

        for (i, entry) in chain.entries.iter_mut().skip(1).enumerate() {
            let step_path = self.step_path_for(i, &entry.post_diff_root);
            if !step_path.exists() { return Err(anyhow!("[#{}] missing step receipt {}", i, step_path.display())); }
            let (step_receipt, step_commit) = self.load_receipt_and_commitment(&step_path)?;
            last_step_rel = Some(step_path.file_name().unwrap().to_string_lossy().into());
            if acc_receipt.is_none() {
                acc_receipt = Some(step_receipt.clone());
                acc_commit = Some(step_commit.clone());
                continue;
            }

            let agg_path = self.fold_path_for(i, &entry.post_diff_root);

            if agg_path.exists() {
                let bytes = fs::read(&agg_path)?;
                let r: Receipt = borsh::from_slice(&bytes)?;
                r.verify(FOLD_ID)?;
                let cm: Commitment = r.journal.decode()?;

                acc_receipt = Some(r.clone());
                acc_commit = Some(cm.clone());
                entry.aggregate_receipt = Some(agg_path.file_name().unwrap().to_string_lossy().into());
                chain.tip_receipt = entry.aggregate_receipt.clone();

                println!("[#{}] existing aggregate, advanced accumulator", i);
                continue;
            }

            let env = ExecutorEnv::builder()
                .add_assumption(acc_receipt.as_ref().unwrap().clone())
                .add_assumption(step_receipt.clone())
                .write(&(acc_commit.as_ref().unwrap().clone(), Some(step_commit.clone())))
                .map_err(|e| anyhow!("[#{}] env write: {}", i, e))?
                .build()
                .map_err(|e| anyhow!("[#{}] env build: {}", i, e))?;

            let prover = default_prover();
            let opts = ProverOpts::succinct();

            println!("[#{}] Folding {} → {}", i, entry.pre_diff_root.as_deref().unwrap_or("-"), entry.post_diff_root);
            let start = std::time::Instant::now();

            let prove_info = prover.prove_with_opts(env, FOLD_ELF, &opts)
                .map_err(|e| anyhow!("[#{}] fold prove failed: {}", i, e))?;
            let folded = prove_info.receipt;

            folded.verify(FOLD_ID)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("[#{}] fold verify failed: {}", i, e)))?;
            println!("[#{}] Fold verified in {:?}", i, start.elapsed());

            let raw = borsh::to_vec(&folded)
                .map_err(|e| anyhow!("[#{}] serialize fold receipt: {}", i, e))?;
            fs::write(&agg_path, raw)
                .with_context(|| format!("[#{}] writing {}", i, agg_path.display()))?;

            entry.step_receipt = Some(step_path.file_name().unwrap().to_string_lossy().into());
            entry.aggregate_receipt = Some(agg_path.file_name().unwrap().to_string_lossy().into());
            chain.tip_receipt = entry.aggregate_receipt.clone();

            let new_cm: Commitment = folded.journal.decode()
                .map_err(|e| anyhow!("[#{}] decode folded journal: {}", i, e))?;
            acc_receipt = Some(folded);
            acc_commit = Some(new_cm);
        }

        if chain.tip_receipt.is_none() {
            if let Some(rel) = last_step_rel {
                chain.tip_receipt = Some(rel);
            }
        }

        self.save_chain(&chain)?;
        println!("✔ Fold pass complete");

        Ok(())
    }

    pub fn cmd_compress_snark(&self, _args: CompressArgs) -> anyhow::Result<()> {
        let wd = self.commitments_dir();
        let mut chain = self.load_chain()?;
        let tip_rel = chain.tip_receipt.clone()
            .ok_or_else(|| anyhow!("No proofs to compress - did you call prove/fold?"))?;
        let tip_path = wd.join(&tip_rel);
        let (receipt, commitment) = self.load_receipt_and_commitment(&tip_path)?;

        let env = ExecutorEnv::builder()
            .add_assumption(receipt)
            .write(&(commitment, None::<Commitment>))
            .map_err(|e| anyhow!("env write: {}", e))?
            .build()
            .map_err(|e| anyhow!("env build: {}", e))?;

        let prover = default_prover();
        let opts = ProverOpts::groth16();
        let info = prover.prove_with_opts(env, FOLD_ELF, &opts)?;
        let snark_path = tip_path.with_extension("snark.bin");

        let raw = borsh::to_vec(&info.receipt)
            .map_err(|e| anyhow!("serialize snark receipt: {}", e))?;
        fs::write(&snark_path, raw)
            .with_context(|| format!("writing {}", snark_path.display()))?;

        chain.tip_receipt_groth16 = Some(snark_path.file_name().unwrap().to_string_lossy().into());
        if let Some(entry) = chain.entries.last_mut() {
            entry.aggregate_groth16 = chain.tip_receipt_groth16.clone();
        }
        self.save_chain(&chain)?;
        println!("✔ Compressed proof");
        println!("   → {}", snark_path.display());

        Ok(())
    }

    pub fn cmd_create(&self, args: RequestArgs) -> Result<(), io::Error> {
        let priv_file = format!("{}.priv", args.handle);
        let priv_path = self.wd.join(&priv_file);

        let script_pubkey = if let Some(ref spk) = args.script_pubkey {
            spk.clone()
        } else {
            let secp = Secp256k1::new();
            let keypair = key::Keypair::new(&secp, &mut rand::thread_rng());

            let secret_key = keypair.secret_key();
            let secret_hex = hex::encode(secret_key.secret_bytes());
            fs::write(&priv_path, secret_hex).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("Failed to write private key: {}", e))
            })?;
            let (xonly_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
            let p2tr_script = ScriptBuf::new_p2tr(&secp, xonly_pubkey, None);
            hex::encode(p2tr_script.as_bytes())
        };

        let subspace_data = HandleRequest {
            handle: args.handle.clone(),
            script_pubkey,
        };

        let pub_file = format!("{}.req.json", args.handle);
        let json_path = self.wd.join(&pub_file);
        let json_str = serde_json::to_string_pretty(&subspace_data).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to serialize JSON: {}", e))
        })?;

        fs::write(&json_path, json_str).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to write JSON file: {}", e))
        })?;

        println!("✔ Created handle request");
        println!("   → {}", pub_file);
        if args.script_pubkey.is_none() {
            println!("   → Private key saved: {}", priv_file);
        }
        println!("\nSubmit the request file to {} operator to get a certificate.", args.handle.space().expect("space"));
        Ok(())
    }

    pub async fn cmd_cert_issue(&self, args: IssueArgs) -> anyhow::Result<()> {
        let client =
            client_from_args(&args.rpc_url, args.rpc_user, args.rpc_password, args.rpc_cookie)?;
        if args.handle.label_count() == 0 || args.handle.label_count() > 2 {
            return Err(anyhow!("specify a valid handle"));
        }

        let space = args.handle.space().expect("space");
        let space_str = space.to_string();

        let space_info = client.get_space(&space_str).await?
            .ok_or_else(|| anyhow!("space does not exist"))?;

        let space_proof = client.prove_ptrout(
            space_info.outpoint(), None
        ).await?;

        let space_inclusion : SubTree<Sha256Hasher> = borsh::from_slice(&space_proof.proof)
            .map_err(|e| anyhow!("could not decode space proof: {}", e))?;

        // Load the space receipt
        let chain = self.load_chain()?;
        let receipt_rel = chain.tip_receipt_groth16
            .or(chain.tip_receipt)
            .ok_or_else(|| anyhow!("No receipt found - run prove first"))?;
        let receipt_path = self.commitments_dir().join(&receipt_rel);
        let (receipt, commitment_info) = self.load_receipt_and_commitment(&receipt_path)?;

        let commitment_proof = client
            .prove_commitment(
                space,
                sha256::Hash::from_slice(&commitment_info.final_root).expect("valid"),
                None
            ).await.map_err(|e| anyhow!("could not prove commitment: {}", e))?;

        let commitment_inclusion : SubTree<Sha256Hasher> = borsh::from_slice(&commitment_proof.proof)
            .map_err(|e| anyhow!("could not decode commitment proof: {}", e))?;

        let root = Certificate {
            subject: args.handle.clone(),
            witness: Witness::Root {
                inclusion: SpacesSubtree(space_inclusion),
                // TODO: include delegate information for the space in this tree
                ptrs: Some(PtrsSubtree(commitment_inclusion)),
                commitment: Some(receipt),
            },
        };

        if args.handle.is_single_label() {
            let out_name = format!("{}.cert.bin", &args.handle);
            let out_path = self.wd.join(&out_name);
            let cert_bytes = borsh::to_vec(&root)
                .map_err(|e| anyhow!("could not serialize root cert: {}", e))?;
            fs::write(&out_path, cert_bytes)?;

            println!("✔ Issued root certificate");
            println!("   → {}", out_name);
            return Ok(());
        }

        // It's a handle so we have to create a handle cert
        let db = self.load_db(&args.handle.space().expect("space"))?
            .ok_or(anyhow!("No database found"))?;
        let mut snap = db.begin_read()?;

        let key = Sha256Hasher::hash(args.handle.subspace().expect("subspace").as_slabel().as_ref());
        let spk = snap.get(&key)?.ok_or_else(|| {
            anyhow!("handle '{}' not found", args.handle)
        })?;

        let subtree = snap.prove(&[key], ProofType::Standard)
            .map_err(|e| anyhow!("could not generate subtree: {}", e))?;

        let sptr = Sptr::from_spk::<Sha256>(ScriptBuf::from_bytes(spk.clone()));
        let ptr_info = client.get_ptr(sptr)
            .await.map_err(|e| anyhow!("could not get ptr: {}", e))?;

        let key_rotation_proof = match ptr_info {
            None => {
                client.prove_ptr_outpoint(sptr).await
                    .map_err(|e| anyhow!("could not prove ptr exclusion: {}", e))?
            }
            Some(info) => {
                client.prove_ptrout(OutPoint {
                    txid: info.txid,
                    vout: info.ptrout.n as _,
                }, None).await
                    .map_err(|e| anyhow!("could not prove ptr inclusion: {}", e))?

            }
        };

        let key_rotation : SubTree<Sha256Hasher> = borsh::from_slice(&key_rotation_proof.proof)
            .map_err(|e| anyhow!("could not decode key rotation proof: {}", e))?;

        let leaf = Certificate {
            subject: args.handle,
            witness: Witness::Leaf {
                genesis_spk: ScriptBuf::from_bytes(spk),
                kind: LeafKind::Final {
                    inclusion: HandleSubtree(subtree),
                    key_rotation: PtrsSubtree(key_rotation),
                }
            },
        };

        // Save root cert
        let root_name = format!("{}.root.cert.bin", &leaf.subject);
        let root_path = self.wd.join(&root_name);
        let root_bytes = borsh::to_vec(&root)
            .map_err(|e| anyhow!("could not serialize root cert: {}", e))?;
        fs::write(&root_path, root_bytes)?;

        // Save leaf cert
        let leaf_name = format!("{}.cert.bin", &leaf.subject);
        let leaf_path = self.wd.join(&leaf_name);
        let leaf_bytes = borsh::to_vec(&leaf)
            .map_err(|e| anyhow!("could not serialize leaf cert: {}", e))?;
        fs::write(&leaf_path, leaf_bytes)?;

        println!("✔ Issued certificates");
        println!("   → {}", root_name);
        println!("   → {}", leaf_name);
        Ok(())
    }

    pub async fn cmd_cert_verify(&self, args: VerifyArgs) -> anyhow::Result<()> {
        let _client =
            client_from_args(&args.rpc_url, args.rpc_user, args.rpc_password, args.rpc_cookie)?;

        // Load the leaf/handle certificate
        let cert_bytes = fs::read(&args.cert_file)
            .with_context(|| format!("reading {}", args.cert_file.display()))?;
        let cert: Certificate = borsh::from_slice(&cert_bytes)
            .map_err(|e| anyhow!("parse {}: {}", args.cert_file.display(), e))?;

        // Load root certificate if provided
        let root_cert: Option<Certificate> = match &args.root {
            Some(root_path) => {
                let root_bytes = fs::read(root_path)
                    .with_context(|| format!("reading {}", root_path.display()))?;
                Some(borsh::from_slice(&root_bytes)
                    .map_err(|e| anyhow!("parse {}: {}", root_path.display(), e))?)
            }
            None => None,
        };

        let anchors = _client.get_root_anchors().await
            .map_err(|e| anyhow!("could not load anchors: {}", e))?;

        let veritas_anchors = serde_json::to_string(&anchors).expect("anchors");
        let veritas_anchors : Vec<libveritas::RootAnchor> = serde_json::from_str(&veritas_anchors)
            .expect("decode anchors");

        let veritas = libveritas::Veritas
        ::from_anchors(veritas_anchors).expect("valid anchors");

        if let Some(root) = root_cert {
            let root_zone = veritas.verify(root, None)?;
            let leaf_zone = veritas.verify(cert, Some(&root_zone))?;

            println!("✔ Certificate verified");
            println!();
            print_zone(&root_zone, "Root");
            println!();
            print_zone(&leaf_zone, "Handle");
        } else {
            let zone = veritas.verify(cert, None)?;

            println!("✔ Certificate verified");
            println!();
            print_zone(&zone, "Root");
        }

        Ok(())
    }

    // pub fn cmd_cert_verify_old(&self, args: VerifyArgs) -> anyhow::Result<()> {
    //     let sub_cert_bytes = fs::read(&args.cert_file)
    //         .with_context(|| format!("reading {}", args.cert_file.display()))?;
    //     let sub_cert: JsonCert = serde_json::from_slice(&sub_cert_bytes)
    //         .map_err(|e| anyhow!("parse {}: {}", args.cert_file.display(), e))?;
    //
    //     let sub_root = match &sub_cert.witness {
    //         JsonWitness::SubTree(st) => {
    //             st.compute_root().map_err(|e| anyhow!("subtree compute_root: {}", e))?
    //         }
    //         JsonWitness::Receipt(_) => {
    //             return Err(anyhow!("{} is a root certificate",
    //                            args.cert_file.display()));
    //         }
    //     };
    //
    //     if args.root.is_none() {
    //         println!("✔ Ready to verify inclusion");
    //         println!("   → handle:   {}", sub_cert.request.handle);
    //         println!("   → genesis:  {}", hex::encode(sub_root));
    //         println!("   → root:     {}", hex::encode(sub_root));
    //         println!("   → history:  {}", hex::encode(sub_root));
    //
    //         println!();
    //         println!("   To verify inclusion, run:");
    //         println!(
    //             "       $ space-cli getcommitment {} {}",
    //             sub_cert.request.handle.space().expect("space"),
    //             hex::encode(sub_root)
    //         );
    //         println!("   ⚠️ Make sure the root, and history hashes match!");
    //         return Ok(());
    //     }
    //     let root_path = args.root.expect("root");
    //
    //     let root_cert_bytes = fs::read(&root_path)
    //         .with_context(|| format!("reading {}", root_path.display()))?;
    //     let root_cert: JsonCert = serde_json::from_slice(&root_cert_bytes)
    //         .map_err(|e| anyhow!("parse {}: {}", root_path.display(), e))?;
    //
    //     if sub_cert.request.handle.space() != root_cert.request.handle.space() {
    //         return Err(anyhow!("invalid root {}, handle's parent is {}",
    //             root_cert.request.handle.space().expect("space"),
    //             sub_cert.request.handle.space().expect("space")
    //         ))
    //     }
    //
    //     if root_cert.request.handle.subspace().expect("subspace") != Label::from_str("self")
    //         .expect("valid") {
    //         return Err(anyhow!("invalid root certificate with non-self subject"))
    //     }
    //
    //     // Verify the receipt, try FOLD first then STEP (root could be aggregate or single step)
    //     let commitment: Commitment = match &root_cert.witness {
    //         JsonWitness::Receipt(receipt) => {
    //             // Try FOLD_ID then STEP_ID
    //             if let Err(e1) = receipt.verify(FOLD_ID) {
    //                 if let Err(e2) = receipt.verify(STEP_ID) {
    //                     return Err(anyhow!("root receipt verify failed: fold={} step={}", e1, e2));
    //                 }
    //             }
    //             receipt.journal.decode()
    //                 .map_err(|e| anyhow!("decode commitment from receipt journal: {}", e))?
    //         }
    //         JsonWitness::SubTree(_) => {
    //             return Err(anyhow!("{} is not a root certificate (expected receipt witness)",
    //                            root_path.display()));
    //         }
    //     };
    //
    //     let root_hash = Sha256Hasher::hash(root_cert.request.handle.space().expect("space").as_ref());
    //     if root_hash != commitment.space {
    //         return Err(anyhow!("bad receipt expected space hash {}, got {}",
    //                            hex::encode(root_hash), hex::encode(commitment.space)));
    //     }
    //
    //     // Compare roots: subtree.compute_root() must match commitment.final_root
    //     let final_root = commitment.final_root.clone();
    //     let genesis_root = commitment.initial_root.clone();
    //     let history_hash = commitment.transcript.clone();
    //     if sub_root != final_root {
    //         return Err(anyhow!(
    //         "root mismatch: subtree={} receipt_final={}",
    //         hex::encode(sub_root),
    //         hex::encode(final_root)
    //     ));
    //     }
    //
    //     if root_cert.anchor != sub_cert.anchor {
    //         return Err(anyhow!(
    //             "anchor mismatch: subspace anchor {} != root anchor {}",
    //             sub_cert.anchor, root_cert.anchor
    //         ));
    //     }
    //
    //
    //     println!("✔ Ready to verify for inclusion");
    //     println!("   → handle : {}", sub_cert.request.handle);
    //     println!("   → genesis: {}", hex::encode(genesis_root));
    //     println!("   → root : {}", hex::encode(final_root));
    //     println!("   → history : {}", hex::encode(history_hash));
    //
    //     println!();
    //     println!("   To verify inclusion, run:");
    //     println!(
    //         "       $ space-cli getcommitment {} {}",
    //         sub_cert.request.handle.space().expect("space"),
    //         hex::encode(final_root)
    //     );
    //     println!("   ⚠️ Make sure the root, and history hashes match!");
    //     Ok(())
    // }
}

impl AddArgs {
    // If user passes a directory find files matching <subspace>@<space>.req.json format.
    pub fn expand_files(&self) -> anyhow::Result<Vec<PathBuf>> {
        let pat = Regex::new(r"^[^/@]+@[^/@]+\.req.json$").unwrap();

        fn collect_dir(dir: &Path, pat: &Regex, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() {
                    collect_dir(&p, pat, out)?;
                } else if p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|name| pat.is_match(name))
                    .unwrap_or(false)
                {
                    out.push(p);
                }
            }
            Ok(())
        }

        let mut out = Vec::new();

        for arg in &self.files {
            let p = PathBuf::from(arg);
            if p.is_dir() {
                collect_dir(&p, &pat, &mut out)?;
            } else {
                out.push(p);
            }
        }

        out.sort();
        out.dedup();
        Ok(out)
    }
}

pub fn client_from_args(rpc_url: &str, rpc_user: Option<String>, rpc_password: Option<String>, rpc_cookie: Option<String>)
    -> anyhow::Result<HttpClient> {
    let auth_token = if rpc_user.is_some() {
        auth_token_from_creds(
            rpc_user.as_ref().unwrap(),
            rpc_password.as_ref().unwrap(),
        )
    } else {
        let cookie_path = match &rpc_cookie {
            Some(path) => path,
            None => return Err(anyhow!("Either specify user/password or a cookie path for rpc auth")),
        };
        let cookie = fs::read_to_string(cookie_path).map_err(|_| {
            anyhow!("Could not read cookie file")
        })?;
        auth_token_from_cookie(&cookie)
    };
    Ok(http_client_with_auth(rpc_url, &auth_token)?)
}

pub fn auth_cookie(user: &str, password: &str) -> String {
    format!("{user}:{password}")
}

pub fn auth_token_from_cookie(cookie: &str) -> String {
    base64::prelude::BASE64_STANDARD.encode(cookie)
}
pub fn auth_token_from_creds(user: &str, password: &str) -> String {
    base64::prelude::BASE64_STANDARD.encode(auth_cookie(user, password))
}

pub struct Sha256;

impl spaces_protocol::hasher::KeyHasher for Sha256 {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}

fn print_zone(zone: &libveritas::Zone, label: &str) {
    println!("{} Zone:", label);
    println!("   handle:     {}", zone.handle);
    println!("   serial:     {}", zone.serial);
    println!("   sovereign:  {}", zone.sovereign);
    println!("   spk:        {}", hex::encode(zone.script_pubkey.as_bytes()));

    if let Some(data) = &zone.data {
        println!("   data:       {}", hex::encode(data.as_slice()));
    }

    match &zone.delegate {
        libveritas::ProvableOption::Exists { value } => {
            println!("   delegate:");
            println!("      spk:     {}", hex::encode(value.script_pubkey.as_bytes()));
            if let Some(data) = &value.data {
                println!("      data:    {}", hex::encode(data.as_slice()));
            }
        }
        libveritas::ProvableOption::Empty => {
            println!("   delegate:   (none)");
        }
        libveritas::ProvableOption::Unknown => {
            println!("   delegate:   (unknown)");
        }
    }

    match &zone.state_root {
        libveritas::ProvableOption::Exists { value } => {
            println!("   state_root: {}", hex::encode(value));
        }
        libveritas::ProvableOption::Empty => {
            println!("   state_root: (none)");
        }
        libveritas::ProvableOption::Unknown => {
            println!("   state_root: (unknown)");
        }
    }
}
