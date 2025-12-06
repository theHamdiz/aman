use clap::{Parser, Subcommand, Args};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use aman::metadata::AmanCertificate;
use aman::fs::{SignerBuilder, VerifierBuilder};
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePublicKey};

// region: CLI Definitions
#[derive(Parser)]
#[command(
    name = "aman", 
    version, 
    about = "Secure Binary Signing & Integrity Tool",
    long_about = "Aman is your companion for securing release artifacts. It helps you sign binaries, manage cryptographic keys, and verify integrity without the headache of OpenSSL arcane commands."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage keys and certificates (e.g., generate Root/Delegate keys)
    #[command(alias = "keygen")]
    Keys(KeysArgs),

    /// Sign a binary with a private key or delegate certificate
    Sign(SignArgs),

    /// Verify a binary's integrity and authenticity
    Verify(VerifyArgs),
}

#[derive(Args)]
struct KeysArgs {
    #[command(subcommand)]
    action: KeyAction,
}

#[derive(Subcommand)]
enum KeyAction {
    /// Generate a standalone keypair (Classic)
    Standalone,
    /// Generate a Root CA keypair
    Root,
    /// Generate a Delegate Keypair and sign it with a Root Key
    Delegate {
        /// Path to Root Private Key PEM
        #[arg(short, long)]
        root_key: String,
        
        /// Validity usage period in days
        #[arg(short, long, default_value_t = 90)]
        days: u64,
    },
}

#[derive(Args)]
struct SignArgs {
    /// Path to the binary to sign
    #[arg(short, long)]
    binary: PathBuf,

    /// Path to Private Key PEM
    #[arg(short = 'k', long)]
    private_key: String,
    
    /// Path to Delegate Certificate (Optional - for Key Rotation)
    #[arg(short = 'c', long)]
    cert: Option<String>,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to the binary to verify
    #[arg(short, long)]
    binary: PathBuf,

    /// Path to the public key PEM file
    #[arg(short = 'k', long)]
    key: PathBuf,
}
// endregion: CLI Definitions

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keys(args) => handle_keys(args),
        Commands::Sign(args) => handle_sign(args),
        Commands::Verify(args) => handle_verify(args),
    }
}

// region: Handlers

fn handle_keys(args: KeysArgs) -> ExitCode {
    use aman::fs::generate_keypair;
    
    match args.action {
        KeyAction::Standalone | KeyAction::Root => {
            let label = match args.action {
                KeyAction::Root => "Root",
                _ => "Standalone",
            };
            println!("Generating {} Keypair...", label);
            
            match generate_keypair() {
                Ok((priv_pem, pub_pem)) => {
                    let priv_name = if label == "Root" { "root.pem" } else { "aman_private.pem" };
                    let pub_name = if label == "Root" { "root.pub" } else { "aman_public.pem" };
                    
                    if let Err(e) = fs::write(priv_name, &priv_pem) {
                        eprintln!("Failed to write {}: {}", priv_name, e);
                        return ExitCode::FAILURE;
                    }
                    if let Err(e) = fs::write(pub_name, &pub_pem) {
                        eprintln!("Failed to write {}: {}", pub_name, e);
                        return ExitCode::FAILURE;
                    }
                    println!("Generated {} and {}", priv_name, pub_name);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("Error generating keys: {}", e);
                    ExitCode::FAILURE
                }
            }
        },
        KeyAction::Delegate { root_key, days } => {
            println!("Generating Delegate Keypair...");
            
            // 1. Generate Delegate Key
            let (del_priv_pem, del_pub_pem) = match generate_keypair() {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Failed to generate delegate key: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            
            // 2. Load Root Key
            let root_pem = match fs::read_to_string(&root_key) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to read root key '{}': {}", root_key, e);
                    return ExitCode::FAILURE;
                }
            };
            
            let root_signer = match SigningKey::from_pkcs8_pem(&root_pem) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Invalid root key: {}", e);
                    return ExitCode::FAILURE;
                }
            };
            
            // 3. Create Certificate
            // Need raw bytes of delegate public key.
            // Helper: parse back the PEM we just made.
            let del_verify_key = p256::ecdsa::VerifyingKey::from_public_key_pem(&del_pub_pem).unwrap();
            let del_pub_der = del_verify_key.to_public_key_der().unwrap().as_bytes().to_vec();
            
            // Calculate Expiry
            let expiry_time = SystemTime::now() + Duration::from_secs(days * 86400);
            let expiry_ts = expiry_time.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            
            // Sign (delegate_pub_key + expiry)
            let mut payload = del_pub_der.clone();
            payload.extend_from_slice(&expiry_ts.to_le_bytes());
            
            use p256::ecdsa::signature::Signer;
            let signature: p256::ecdsa::Signature = root_signer.sign(&payload);
            
            let cert = AmanCertificate {
                kid: "delegate".to_string(), // In real world this would be computed
                delegate_pub_key: del_pub_der,
                expiry: expiry_ts,
                root_signature: signature.to_vec(),
            };
            
            // Save files
            if let Err(e) = fs::write("delegate.pem", del_priv_pem) {
                eprintln!("Failed to write delegate.pem: {}", e);
                 return ExitCode::FAILURE;
            }
            let cert_json = serde_json::to_string_pretty(&cert).unwrap();
            if let Err(e) = fs::write("delegate.cert", cert_json) {
                eprintln!("Failed to write delegate.cert: {}", e);
                 return ExitCode::FAILURE;
            }
            
            println!("Generated 'delegate.pem' and 'delegate.cert' (Valid for {} days)", days);
            ExitCode::SUCCESS
        }
    }
}

fn handle_sign(args: SignArgs) -> ExitCode {
    let key_pem = match fs::read_to_string(&args.private_key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read private key: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let mut builder = SignerBuilder::new(&args.binary)
        .add_p256(&key_pem); // Assuming P256 defaulting for now
        
    if let Some(cert_path) = args.cert {
        let cert_json = match fs::read_to_string(&cert_path) {
            Ok(c) => c,
             Err(e) => {
                eprintln!("Failed to read certificate: {}", e);
                return ExitCode::FAILURE;
            }
        };
        
        builder = match builder.set_certificate_json(&cert_json) {
             Ok(b) => b,
             Err(e) => {
                 eprintln!("Invalid certificate: {}", e);
                 return ExitCode::FAILURE;
             }
        };
    }
    
    match builder.execute() {
        Ok(_) => {
            println!("Binary signed successfully!");
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("Error signing binary: {}", e);
            ExitCode::FAILURE
        }
    }
}

fn handle_verify(args: VerifyArgs) -> ExitCode {
     let public_pem = match std::fs::read_to_string(&args.key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read public key: {}", e);
            return ExitCode::FAILURE;
        }
    };

    let verifier = VerifierBuilder::new(args.binary.clone()).trust_p256(&public_pem);

    match verifier.verify() {
        Ok(_) => {
            println!("✅ Verification Passed. Binary integrity confirmed.");
            ExitCode::SUCCESS
        },
        Err(e) => {
            eprintln!("❌ Verification Failed: {}", e);
            ExitCode::FAILURE
        }
    }
}
// endregion: Handlers
