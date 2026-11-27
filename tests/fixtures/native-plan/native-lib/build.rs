fn main() {
    println!("cargo::metadata=token=dependency-metadata");
    println!("cargo::rustc-env=FIXTURE_NUMBER=41");
}
