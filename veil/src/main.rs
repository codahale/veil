use veil_lib::SecretKey;

fn main() {
    let sk = SecretKey::new();

    println!("{:?}", sk.public_key("/woot/boot"));
}
