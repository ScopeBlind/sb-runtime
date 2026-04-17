# Basic example

Run an allowed command:
```bash
sb exec \
  --policy examples/basic/policy.cedar \
  --receipts /tmp/sb-example \
  --allow-unsandboxed \
  -- /usr/bin/cat /etc/hosts
```

Run a denied command (exit 2, receipt still emitted):
```bash
sb exec \
  --policy examples/basic/policy.cedar \
  --receipts /tmp/sb-example \
  --allow-unsandboxed \
  -- /usr/bin/rm -rf /tmp/something
```

Verify the chain:
```bash
sb verify /tmp/sb-example
# ✓ 2 receipts verified (...)

# Or using the Node verifier (same format):
npx @veritasacta/verify /tmp/sb-example
```

Tamper with a receipt and re-verify:
```bash
sed -i '' 's/"allow"/"deny"/' /tmp/sb-example/000001.json
sb verify /tmp/sb-example
# Error: signature error: Verification equation was not satisfied
```
