use std::fs;
use std::process::ExitCode;

#[derive(Debug, PartialEq, Eq)]
pub struct KernelProbe {
    pub landlock_enabled: bool,
    pub userns_allowed: bool,
}

pub fn probe_kernel() -> KernelProbe {
    let lsm = fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
    let landlock_enabled = lsm.split(',').any(|entry| entry.trim() == "landlock");

    // On Arch linux-hardened, unprivileged_userns_clone may be 0; if absent, default is allowed.
    let userns_allowed = match fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(val) => val.trim() != "0",
        Err(_) => true,
    };

    KernelProbe {
        landlock_enabled,
        userns_allowed,
    }
}

fn main() -> ExitCode {
    let probe = probe_kernel();
    println!(
        "{{\"landlock\":{},\"unprivileged_userns\":{}}}",
        probe.landlock_enabled, probe.userns_allowed
    );

    if !probe.landlock_enabled || !probe.userns_allowed {
        eprintln!(
            "snarx-sandbox: FAIL-CLOSED — kernel containment prerequisites not met (landlock={}, userns={}).",
            probe.landlock_enabled, probe.userns_allowed
        );
        return ExitCode::from(2);
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_runs_without_panicking() {
        let _ = probe_kernel();
    }
}
