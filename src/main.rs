use crypto::digest::digest;
use crypto::rsaPublicKey;
use crypto::rsaPrivateKey;
use crypto::sha2::Sha256;
use crypto::signature::Signer;
use crypto::signature::Verifier;
#[derive(Debug)]


// Fonction pour générer une paire de clés RSAc
fn generate_rsa_keypair() -> (PrivateKey, PublicKey) {

    let private_key = PrivateKey::new_rsa(2048).unwrap();

    let public_key = private_key.public_key().unwrap();
    
    (private_key, public_key)

}


// Fonction pour hacher un message
fn hash_message(message: &str) -> Vec<u8> {

    let digest = digest::Sha256::new();

    let mut hasher = digest.clone();

    hasher.update(message.as_bytes());

    let mut digest_bytes = vec![0; hasher.output_size()];

    hasher.finalize(&mut digest_bytes);

    digest_bytes

}


// Fonction pour signer un message avec une clé privée
fn sign_message(message: &str, private_key: &PrivateKey) -> Vec<u8> {

    let signer = Signer::new(private_key);

    let mut signature_bytes = vec![0; signer.signature_length(message.as_bytes().len())];

    signer.sign(message.as_bytes(), &mut signature_bytes).unwrap();

    signature_bytes

}

// Fonction pour vérifier une signature avec une clé publique
fn verify_signature(message: &str, signature: &[u8], public_key: &PublicKey) -> bool {

    let verifier = Verifier::new(public_key);

    verifier.verify(message.as_bytes(), signature).unwrap()

}

// Fonction pour créer un bloc de blockchain
fn create_block(previous_hash: &[u8], transactions: Vec<String>) -> Vec<u8> {

    let block_data = format!("{:?}:{:?}", transactions, previous_hash);

    let block_hash = hash_message(&block_data);

    let block = format!("{:?}:{:?}", block_hash, block_data);

    block.as_bytes().to_vec()

}

fn main() {

    // Générer une paire de clés RSA
    let (private_key, public_key) = generate_rsa_keypair();
    // Hacher un message
    let message = "Ceci est un message à signer";

    let message_hash = hash_message(message);
    // Signer le message avec la clé privée
    let signature = sign_message(message, &private_key);
    // Vérifier la signature avec la clé publique
    let is_valid = verify_signature(message, &signature, &public_key);

    println!("Signature valide: {:?}", is_valid);
    // Créer un bloc de blockchain
    let previous_hash = [0; 32]; // Hash du bloc précédent

    let transactions = vec!["Transaction 1", "Transaction 2"];

    let block = create_block(&previous_hash, transactions);

    println!("Bloc de blockchain: {:?}", block);

}
