<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="SRE Toolbox" />
  </a>
</p>

<h1 align="center">SSL Expiry</h1>

Check TLS certificate expiration dates on port 443.

`lupaxa-ssl-expiry` connects to each host, reads the leaf certificate the
server presents, and reports the issuer, the expiration date, and how many
days remain. The handshake requires TLS 1.2 or newer. Hostname matching and
certificate trust are not checked, so an expired, self-signed, or untrusted
leaf is still reported. The TCP port is always 443.

## Requirements

- Python 3.13 or newer
- Outbound TCP access to port 443

`cryptography` and `prettytable` install with the package.

## Install

```bash
pip install lupaxa-ssl-expiry
ssl-expiry --help
```

## CLI

```bash
ssl-expiry example.com example.org
ssl-expiry example.com,example.org
ssl-expiry --file hosts.txt --warn-days 14
printf '%s\n' example.com example.org | ssl-expiry --file -
ssl-expiry --sort days --order descending example.com example.org
python -m lupaxa.ssl_expiry --version
```

Pass hosts as separate arguments, or separate them with commas. International
names are converted to ASCII before the connection, and that form is what
the host column prints. IPv4 and IPv6 addresses are accepted. A URL, a port
suffix, or any other non-host is invalid and is not connected.

`--file` reads one hostname per line. Blank lines and `#` comments are
ignored. `-` reads stdin. Repeat `--file` to combine lists. Hosts on the
command line are checked first, then hosts from each file.

`--timeout` is the TCP connect and TLS handshake timeout in seconds
(default `10`). It must be greater than `0`.

`--warn-days` is how close a date can be before the command exits `1`
(default `30`). The comparison is inclusive: a certificate with `30` days
left exits `1` when `--warn-days` is `30`. `0` means only today or earlier.

`--sort` orders the table by `host`, `issuer`, `date`, or `days`.
`--order` is `ascending` (the default) or `descending`. `asc` and `desc`
are accepted. Host and issuer order ignore case. Date order uses the
expiration date, including hosts that show `Expired`. Day order uses the
day count. Rows with no issuer, date, or day count stay at the end.
Without `--sort`, rows stay in the order the hosts were given. `--order`
without `--sort` exits `2`.

With no hosts, the command prints help and exits `2`.

## Output

Results print as one table. Every host is a row, including invalid hosts
and connection failures.

```text
+--------------+---------------+---------------------+------+
| Host         | Issuer        | Date                | Days |
+--------------+---------------+---------------------+------+
| example.com  | Let's Encrypt | 15th March 2027     |  173 |
| example.org  | DigiCert Inc  | 22nd September 2026 |    0 |
| old.example  | Let's Encrypt | Expired             |  -12 |
| slow.test    | —             | timed out           |    — |
| nope.invalid | —             | Invalid Host        |    — |
+--------------+---------------+---------------------+------+
```

The date is the day, with `st`, `nd`, `rd`, or `th`, then the month name
and the year, as in `11th November 2026`. `Expired` means that date is
already past. `Days` is the number of UTC calendar days remaining. `0`
means the certificate expires today. A negative number is how many days
ago it expired.

The issuer is the certificate organization name, or its common name when
the organization is absent. When neither is present, the issuer column
shows `—`.

`Invalid Host` means the value was not connected. A connection failure,
including a timeout or a handshake that yields no certificate, puts the
cleaned error in the date column. Examples include `timed out` and
`no peer certificate`.

## Exit Codes

| Code | When                                                                                 |
| :--- | :----------------------------------------------------------------------------------- |
| `0`  | Help, version, or every certificate is further out than `--warn-days`                |
| `1`  | A certificate is due, expired, or the host is invalid                                |
| `2`  | Usage failed, a file could not be read, no hosts were given, or a connection failed  |

When one host needs attention and another connection fails, the command
exits `1`.

## Library

```python
from lupaxa.ssl_expiry import lookup

result = lookup("example.com", timeout=10.0)
if result.status == "expires":
    print(result.issuer, result.expiration, result.days_remaining)
else:
    print(result.status, result.error)
```

`lookup` returns a result for invalid hosts and connection failures.
`status` is `expires`, `invalid`, or `error`. `days_remaining` is set only
for `expires`. `error` is set only for `error`, and is a single line. An
invalid host is not connected. A timeout that is not greater than `0`
raises `ValueError`.

Pass `now` to fix the clock used for `days_remaining`. Pass `probe` to
replace the network call in tests. The callable receives the normalized
host and the timeout in seconds, and returns a `LeafCert`.

## Development

```bash
make init
make python-install-dev
make python-check
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
