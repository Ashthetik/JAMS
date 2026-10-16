## Summary

<!-- What does this PR do, and why? One or two sentences. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] Security fix
- [ ] New feature
- [ ] Refactor (no behaviour change)
- [ ] Documentation / tooling
- [ ] Breaking change (config, DB schema, on-disk format, or protocol behaviour)

## Affected components

- [ ] SMTP (port 25)
- [ ] Submission (port 587)
- [ ] IMAP (ports 143 / 993)
- [ ] TLS
- [ ] io_uring event loop
- [ ] DNS resolver
- [ ] Auth / credential store
- [ ] SPF / DKIM / DMARC
- [ ] Maildir storage
- [ ] Config / admin tooling

## Changes

<!-- List the key changes. Call out anything a reviewer should look at closely. -->

-

## Testing

- [ ] Builds cleanly with `-Wall -Wextra -Wpedantic`
- [ ] Debug build runs clean under ASan and UBSan (no new reports)
- [ ] Integration tests pass (`pytest tests/integration`)
- [ ] New or updated tests cover this change
- [ ] Manually tested against a real client (Outlook, Thunderbird, `openssl s_client`, `swaks`, etc.)

<!-- Paste relevant log output, protocol transcripts, or test results. Redact credentials, peppers, and personal addresses. -->

```
```

## Security checklist

- [ ] All external input (SMTP/IMAP commands, addresses, headers, literals) is validated before use
- [ ] No credentials, peppers, tokens, or message bodies are written to logs
- [ ] SQL uses prepared statements with bound parameters only
- [ ] Filesystem paths built from user input are validated (no `/` or `..` traversal)
- [ ] Port 25 still rejects non-local recipients (no open relay)
- [ ] AUTH still requires TLS
- [ ] fd / io_uring lifecycle is respected (no close while SQEs are in flight)
- [ ] Threat matrix in the README updated if this adds or mitigates a threat

## Protocol compliance

<!-- If this touches protocol behaviour, cite the RFC section(s) followed (e.g. RFC 5321 §4.5.3, RFC 3501 §6.4.5, RFC 2177). Write N/A otherwise. -->

## Deployment notes

- [ ] No DB schema change
- [ ] No config (`server.toml`) change
- [ ] No new environment variables
- [ ] No change to on-disk Maildir format

<!-- If any box above is unchecked, describe the migration steps here. -->
