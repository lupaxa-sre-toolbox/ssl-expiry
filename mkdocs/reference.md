# Reference

## Commands

| Command                       | Role                                     |
| :---------------------------- | :--------------------------------------- |
| `ssl-expiry`                  | The installed command                    |
| `python -m lupaxa.ssl_expiry` | The same program, run as a Python module |

## CLI arguments

| Flag                | Default   | Description                                                  |
| :------------------ | :-------- | :----------------------------------------------------------- |
| `HOST`              | optional  | Hostname; repeat for more than one                           |
| `--file`, `-f`      | none      | Text file of hosts, one per line; `-` reads stdin            |
| `--timeout`, `-t`   | `10`      | TCP connect and TLS handshake timeout in seconds             |
| `--warn-days`, `-w` | `30`      | Exit `1` when a certificate expires within this many days    |
| `--sort`, `-s`      | none      | Sort by `host`, `issuer`, `date`, or `days`                  |
| `--order`           | ascending | `ascending` or `descending`; requires `--sort`               |
| `--version`         | —         | Print the package version and exit                           |

`--timeout` must be greater than `0`. `--warn-days` must be `0` or greater.
`--order` accepts `ascending`, `descending`, `asc`, or `desc`.
Pass several hosts as separate arguments, or separate them with commas.
With no hosts, the command prints the same text as `--help` and exits `2`.
The TCP port is 443.

## Exit codes

| Code | When                                                                                 |
| :--- | :----------------------------------------------------------------------------------- |
| `0`  | Help, version, or every certificate is further out than `--warn-days`                |
| `1`  | A certificate is due, expired, or the host is invalid                                |
| `2`  | Usage failed, a file could not be read, no hosts were given, or a connection failed  |

When one host needs attention and another connection fails, the command
exits `1`.

## Library

| Name                 | Meaning                                                          |
| :------------------- | :--------------------------------------------------------------- |
| `lookup`             | Check one host and return an `ExpiryResult`                      |
| `probe_certificate`  | Connect and return a `LeafCert` for the presented leaf           |
| `ExpiryResult`       | Frozen result: host, status, issuer, expiration, days, and error |
| `LeafCert`           | `not_after`, `issuer_organization`, and `issuer_common_name`     |
| `DEFAULT_TIMEOUT`    | Default connection timeout (`10.0` seconds)                      |
| `DEFAULT_WARN_DAYS`  | Default warning window (`30` days)                               |
| `get_version()`      | Return the package version string                                |

`status` is `expires`, `invalid`, or `error`. `days_remaining` is set only
for `expires`. It is the difference of the UTC calendar dates, so a date
later today is `0`. `error` is set only for `error`, and is a single line.
The issuer string is the organization name, then the common name, then
nothing.

An empty name, a URL, a port suffix, or any other non-host is `invalid`
and is not connected. DNS names do not need a public top-level domain.
IPv4 and IPv6 addresses are accepted. A non-positive timeout raises
`ValueError`.
