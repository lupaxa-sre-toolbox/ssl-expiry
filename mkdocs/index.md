# SSL Expiry

`lupaxa-ssl-expiry` checks when the TLS certificate on port 443 expires.
It reads the leaf certificate the server presents and prints the issuer,
the date, and how many days remain.

```bash
pip install lupaxa-ssl-expiry
ssl-expiry example.com
```

Results print as a table with the host, the issuer, the date, and the days
remaining. Every host is a row. A past date shows `Expired`. A value that
is not a hostname shows `Invalid Host`. A connection that yields no
certificate shows the error in the date column.

## Next steps

- [Getting started](getting-started.md) — install and first run
- [Usage](usage.md) — output, CLI flags, and the library API
- [Reference](reference.md) — defaults, exit codes, and API names
- [Examples](examples.md) — common check recipes
