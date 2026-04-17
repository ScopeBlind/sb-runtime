// Cedar policy used by the SbRuntimeSkill smoke test and by a sensible
// "allow read-only utilities, forbid destructive commands" default for
// developer laptops.

permit (
  principal == Agent::"self",
  action == Action::"exec",
  resource
) when {
  resource == Command::"/bin/cat"     ||
  resource == Command::"/bin/echo"    ||
  resource == Command::"/bin/ls"      ||
  resource == Command::"/bin/true"    ||
  resource == Command::"/usr/bin/cat" ||
  resource == Command::"/usr/bin/echo" ||
  resource == Command::"/usr/bin/ls"  ||
  resource == Command::"/usr/bin/env"
};

// Destructive commands — explicitly forbidden so they log as deny
// even if a broader permit snuck in elsewhere.
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
forbid (
  principal,
  action == Action::"exec",
  resource == Command::"/bin/dd"
);
