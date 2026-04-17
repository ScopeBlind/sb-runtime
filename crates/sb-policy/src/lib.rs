//! Cedar-backed policy evaluation for `sb-runtime`.
//!
//! A thin, ergonomic wrapper around the `cedar-policy` crate that evaluates
//! agent actions (e.g. `exec`, `open`, `connect`) against a user-supplied
//! Cedar policy file before the sandbox actually runs them.
//!
//! The intent is deliberately narrow: we're not reimplementing Cedar. We're
//! giving `sb exec` a one-line call site:
//!
//! ```ignore
//! let eval = Evaluator::from_file("policy.cedar")?;
//! let decision = eval.evaluate_exec("/usr/bin/rm", &["-rf", "/"])?;
//! assert!(matches!(decision, Decision::Deny { .. }));
//! ```

use std::fs;
use std::path::Path;

use cedar_policy::{Authorizer, Context, Entities, EntityUid, PolicySet, Request, Schema};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("I/O error reading policy: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cedar policy parse error: {0}")]
    Parse(String),
    #[error("Cedar request build error: {0}")]
    Request(String),
    #[error("Cedar authorization error: {0}")]
    Authorize(String),
}

/// Decision returned by the evaluator.
#[derive(Debug, Clone)]
pub enum Decision {
    Allow {
        /// The `policy_id` string to record in the receipt.
        policy_id: String,
    },
    Deny {
        policy_id: String,
        /// Human-readable reason (best-effort — Cedar's diagnostics verbatim).
        reason: String,
    },
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }
    pub fn policy_id(&self) -> &str {
        match self {
            Decision::Allow { policy_id } => policy_id,
            Decision::Deny { policy_id, .. } => policy_id,
        }
    }
}

/// Cedar evaluator bound to a specific policy set + (optional) schema.
pub struct Evaluator {
    policies: PolicySet,
    authorizer: Authorizer,
    policy_id: String,
    #[allow(dead_code)]
    schema: Option<Schema>,
}

impl Evaluator {
    /// Load a policy set from a file path. The "policy id" used in emitted
    /// receipts defaults to the file stem; callers can override with
    /// [`Self::with_policy_id`].
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let src = fs::read_to_string(path)?;
        let policies = src
            .parse::<PolicySet>()
            .map_err(|e| PolicyError::Parse(e.to_string()))?;
        let policy_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("policy")
            .to_string();
        Ok(Self {
            policies,
            authorizer: Authorizer::new(),
            policy_id,
            schema: None,
        })
    }

    /// Override the policy id reported in receipts.
    #[must_use]
    pub fn with_policy_id(mut self, id: impl Into<String>) -> Self {
        self.policy_id = id.into();
        self
    }

    /// Evaluate an `exec` action against the bound policy set.
    ///
    /// The Cedar principal is `Agent::"self"`, action is
    /// `Action::"exec"`, resource is `Command::"<path>"`. The command
    /// arguments are exposed as a string array in the request context.
    pub fn evaluate_exec(
        &self,
        command_path: &str,
        args: &[String],
    ) -> Result<Decision, PolicyError> {
        let principal: EntityUid = "Agent::\"self\""
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| PolicyError::Request(e.to_string()))?;
        let action: EntityUid = "Action::\"exec\""
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| PolicyError::Request(e.to_string()))?;
        let resource: EntityUid = format!("Command::\"{command_path}\"")
            .parse()
            .map_err(|e: cedar_policy::ParseErrors| PolicyError::Request(e.to_string()))?;

        let args_json = serde_json::json!({ "args": args });
        let context = Context::from_json_value(args_json, None)
            .map_err(|e| PolicyError::Request(e.to_string()))?;

        let request = Request::new(principal, action, resource, context, self.schema.as_ref())
            .map_err(|e| PolicyError::Request(e.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &Entities::empty());

        match response.decision() {
            cedar_policy::Decision::Allow => Ok(Decision::Allow {
                policy_id: self.policy_id.clone(),
            }),
            cedar_policy::Decision::Deny => {
                let reason = response
                    .diagnostics()
                    .reason()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let reason = if reason.is_empty() {
                    "implicit deny (no permit matched)".to_string()
                } else {
                    format!("deny policies: {reason}")
                };
                Ok(Decision::Deny {
                    policy_id: self.policy_id.clone(),
                    reason,
                })
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(name: &str, src: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sb-policy-test-{name}.cedar"));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(src.as_bytes()).unwrap();
        path
    }

    #[test]
    fn permit_allows_matching_command() {
        let path = write_tmp(
            "permit",
            r#"
            permit(
              principal == Agent::"self",
              action == Action::"exec",
              resource == Command::"/usr/bin/cat"
            );
            "#,
        );
        let eval = Evaluator::from_file(&path).unwrap();
        let d = eval.evaluate_exec("/usr/bin/cat", &[]).unwrap();
        assert!(d.is_allow());
    }

    #[test]
    fn implicit_deny_when_no_permit_matches() {
        let path = write_tmp(
            "deny",
            r#"
            permit(
              principal == Agent::"self",
              action == Action::"exec",
              resource == Command::"/usr/bin/cat"
            );
            "#,
        );
        let eval = Evaluator::from_file(&path).unwrap();
        let d = eval
            .evaluate_exec("/usr/bin/rm", &["-rf".into(), "/".into()])
            .unwrap();
        assert!(!d.is_allow());
    }

    #[test]
    fn explicit_forbid_overrides_permit() {
        let path = write_tmp(
            "forbid",
            r#"
            permit(principal, action, resource);
            forbid(
              principal,
              action == Action::"exec",
              resource == Command::"/usr/bin/rm"
            );
            "#,
        );
        let eval = Evaluator::from_file(&path).unwrap();
        assert!(eval.evaluate_exec("/usr/bin/cat", &[]).unwrap().is_allow());
        assert!(!eval.evaluate_exec("/usr/bin/rm", &[]).unwrap().is_allow());
    }
}
