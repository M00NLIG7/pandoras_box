use super::mission::TransportKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationMutability {
    ReadOnly,
    Mutating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionPolicy {
    pub dry_run: bool,
    pub allow_smb_fallback: bool,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            dry_run: false,
            allow_smb_fallback: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyViolation {
    message: String,
}

impl PolicyViolation {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PolicyViolation {}

impl ExecutionPolicy {
    pub fn allow_transport(&self, transport: TransportKind) -> Result<(), PolicyViolation> {
        if transport == TransportKind::WindowsSmb && !self.allow_smb_fallback {
            return Err(PolicyViolation::new(
                "SMB fallback is disabled by transport policy",
            ));
        }

        Ok(())
    }

    pub fn allow_operation(&self, mutability: OperationMutability) -> Result<(), PolicyViolation> {
        if self.dry_run && mutability == OperationMutability::Mutating {
            return Err(PolicyViolation::new(
                "dry-run blocks remote mutation operations",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ExecutionPolicy, OperationMutability};
    use crate::runtime::mission::TransportKind;

    #[test]
    fn policy_blocks_mutation_operations_in_dry_run() {
        let policy = ExecutionPolicy {
            dry_run: true,
            allow_smb_fallback: true,
        };

        assert!(policy
            .allow_operation(OperationMutability::Mutating)
            .is_err());
        assert!(policy
            .allow_operation(OperationMutability::ReadOnly)
            .is_ok());
    }

    #[test]
    fn policy_can_disable_smb_fallback() {
        let policy = ExecutionPolicy {
            dry_run: false,
            allow_smb_fallback: false,
        };

        assert!(policy.allow_transport(TransportKind::WindowsSmb).is_err());
        assert!(policy.allow_transport(TransportKind::WindowsSsh).is_ok());
    }
}
