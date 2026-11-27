pub fn value() -> u32 {
    env!("FIXTURE_NUMBER").parse().unwrap()
}
