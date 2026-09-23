# Usage

## Output

Results print as one table.

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

The date is the day, with `st`, `nd`, `rd`, or `th`, then the month
name and the year, as in `11th November 2026`. `Expired` means that date is
already past. `Days` is the number of UTC calendar days remaining. `0` means
the certificate expires today. A negative number is how many days ago it
expired.

`Invalid Host` means the value was not connected: it is empty, not a
hostname, or includes a port or URL. A connection failure, including a
timeout or a handshake that yields no certificate, puts the cleaned error
in the date column. Examples include `timed out` and `no peer certificate`.
Every host is a row.

The issuer is the certificate organization name, or its common name when
the organization is absent. When neither is present, the issuer column shows
`—`.

International names are converted to ASCII before the connection, and that
form is what the host column prints.

## CLI

```bash
ssl-expiry example.com example.org example.net
ssl-expiry example.com,example.org
ssl-expiry --file hosts.txt --warn-days 14
ssl-expiry --file - --timeout 5
ssl-expiry --sort host example.org example.com
ssl-expiry --sort days --order descending example.com example.org
```

With no hosts, the command prints help and exits `2`.

`--file` reads one hostname per line. Blank lines and `#` comments are
ignored. `-` reads stdin. Repeat `--file` to combine lists. Hosts on the
command line are checked first, then hosts from each file.

`--timeout` is the TCP connect and TLS handshake timeout, in seconds. It
must be greater than `0`.

`--warn-days` is how close a date can be before the command exits `1`. The
comparison is inclusive: a certificate with `30` days left exits `1` when
`--warn-days` is `30`. `0` means only today or earlier. Expired and invalid
hosts also exit `1`. A failed connection, including a timeout, exits `2`.
When one host needs attention and another connection fails, the command
exits `1`.

`--sort` orders the table by `host`, `issuer`, `date`, or `days`. `--order`
is `ascending` (the default) or `descending`. `asc` and `desc` are accepted.
Host order is alphabetical and ignores case. Date order uses the expiration
date, including hosts that show `Expired`. Day order uses the day count.
Rows with no issuer, date, or day count stay at the end. Without `--sort`,
rows stay in the order the hosts were given. `--order` without `--sort`
exits `2`.

The TCP port is always 443.

## Library

```python
from lupaxa.ssl_expiry import lookup

result = lookup("example.com", timeout=10.0)
if result.status == "expires":
    print(result.issuer, result.expiration, result.days_remaining)
else:
    print(result.status, result.error)
```

`lookup` returns a result for invalid hosts and connection failures,
including a timeout. An invalid host has status `invalid` and is not
connected. It raises `ValueError` when `timeout` is not greater than `0`.

Pass `now` to fix the clock used for `days_remaining`. Pass `probe` to
replace the network call in tests. The callable receives the normalized
host and the timeout in seconds, and returns a `LeafCert`.

The probe returns the presented leaf certificate even when it is expired,
self-signed, or untrusted. Hostname verification and trust checks are off.
