#[test]
fn explicit_shortcuts_spawn_in_the_right_directory_without_shell_interpolation() {
    let output = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/launch.py"))
        .arg(env!("CARGO_BIN_EXE_devmon"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

#[test]
fn private_bus_is_responsive_coalesced_and_stops_observing() {
    let output = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/service.py"))
        .args([env!("CARGO_BIN_EXE_enzimos-dev-monitor"), env!("CARGO_BIN_EXE_devmon")])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
