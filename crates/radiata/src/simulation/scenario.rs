#[cfg(test)]
mod tests {
  use radiata_test_support::{
    ApprovedCorpusDigest, CargoTestId, ExecutableId, FuzzTarget, ReplayError, ReplaySpec,
  };

  #[test]
  fn simulation_failure_artifact_security_replay_is_closed_and_canonical() {
    let replay = ReplaySpec::simulation_network_fault_matrix(42);
    assert_eq!(replay.executable_id(), ExecutableId::Simulation);
    assert_eq!(
      replay.argv(),
      ["--scenario", "network-fault-matrix", "--seed", "42"],
    );
    assert_eq!(
      ReplaySpec::parse("simulation", &replay.argv()),
      Ok(replay.clone())
    );
    assert_eq!(
      replay.materialize().args(),
      [
        "--config",
        "env.RADIATA_SIM_SEED.value=\"42\"",
        "--config",
        "env.RADIATA_SIM_SEED.force=true",
        "test",
        "--locked",
        "--lib",
        crate::simulation::artifact::MATRIX_REPLAY_TEST_FILTER,
        "--",
        "--ignored",
        "--exact",
      ],
    );
  }

  #[test]
  fn simulation_failure_artifact_security_cargo_and_fuzz_replay_are_allowlisted() {
    let cargo = ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity);
    assert_eq!(cargo.executable_id(), ExecutableId::CargoTest);
    assert_eq!(ReplaySpec::parse("cargo-test", &cargo.argv()), Ok(cargo));

    let fuzz = ReplaySpec::fuzz_corpus(
      FuzzTarget::WireDecode,
      ApprovedCorpusDigest::from_reviewed_bytes([0x33; 32]),
    );
    assert_eq!(fuzz.executable_id(), ExecutableId::FuzzCorpus);
    assert_eq!(ReplaySpec::parse("fuzz-corpus", &fuzz.argv()), Ok(fuzz));
  }

  #[test]
  fn simulation_failure_artifact_security_replay_rejects_hostile_input() {
    let oversized = "7".repeat(65);
    let hostile_cases = [
      (
        "/tmp/cargo",
        vec!["--locked", "--lib", "simulation_failure_artifact_security"],
      ),
      (
        "cargo;sh",
        vec!["--locked", "--lib", "simulation_failure_artifact_security"],
      ),
      (
        "simulation",
        vec!["--scenario", "../fault-matrix", "--seed", "1"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "01"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "+1"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "$(id)"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "1\n2"],
      ),
      ("simulation", vec!["--config", "env.SECRET", "--seed", "1"]),
      (
        "simulation",
        vec![
          "--scenario",
          "network-fault-matrix",
          "--seed",
          oversized.as_str(),
        ],
      ),
      ("cargo-test", vec!["--locked", "--lib", "../../test"]),
      (
        "fuzz-corpus",
        vec!["--target", "../../wire", "--entry", "00"],
      ),
    ];
    for (executable, argv) in hostile_cases {
      let result = ReplaySpec::parse(executable, &argv);
      assert_eq!(result, Err(ReplayError::InvalidSpec));
      let diagnostic = format!("{result:?}");
      assert!(!diagnostic.contains("SECRET"));
      assert!(!diagnostic.contains("$(id)"));
      assert!(!diagnostic.contains("../../"));
    }
  }
}
