#[cfg(fixture_generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn main() {
    assert_eq!(native_lib::value(), 41);
    assert_eq!(fixture_derive::one!(), 1);
    assert_eq!(TOKEN, "dependency-metadata");
    assert_eq!(env!("FIXTURE_ENV"), "build-script");
    println!("native-plan-ok");
}
