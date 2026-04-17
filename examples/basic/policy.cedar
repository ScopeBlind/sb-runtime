// Basic dev policy for sb-runtime.
//
// Permits read-only utilities and shell pipelines; denies obviously
// destructive commands. Every evaluation emits a signed receipt,
// regardless of outcome.

permit (
  principal == Agent::"self",
  action == Action::"exec",
  resource
) when {
  resource == Command::"/bin/cat" ||
  resource == Command::"/bin/ls"  ||
  resource == Command::"/bin/echo" ||
  resource == Command::"/usr/bin/cat" ||
  resource == Command::"/usr/bin/ls" ||
  resource == Command::"/usr/bin/echo" ||
  resource == Command::"/usr/bin/env"
};

forbid (
  principal,
  action == Action::"exec",
  resource == Command::"/bin/rm"
);

forbid (
  principal,
  action == Action::"exec",
  resource == Command::"/usr/bin/rm"
);
