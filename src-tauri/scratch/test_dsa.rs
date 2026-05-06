use dilithium_rs::MlDsa65;

fn main() {
    let (pk, sk) = MlDsa65::generate();
    let msg = b"test";
    let sig = MlDsa65::sign(&sk, msg);
    assert!(MlDsa65::verify(&pk, msg, &sig).is_ok());
    println!("ML-DSA-65 works!");
}
