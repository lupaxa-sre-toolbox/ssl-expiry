<!-- markdownlint-disable -->
<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="Project Logo" width="256"/><br/>
  </a>
</p>
<h3 align="center">
  The Lupaxa SRE Toolbox<br />
  Part of The Lupaxa Project
</h3>

<br />

# lupaxa-ssl-expiry

Check TLS certificate expiration dates on port 443.

## Features

- Query one or more hostnames and print one table
- Read hosts from a file, or from stdin with `--file -`
- Report the issuer, the expiration date, and the number of days remaining
- Keep every host in the table, including invalid hosts and connection failures
- Keep connection errors separate from expiry
- Exit `1` when a certificate expires within `--warn-days`
- Sort the table by host, issuer, date, or days, ascending or descending
- Use the `lookup` library API
- Depend on `cryptography` and `prettytable` at runtime

## Installation

### From PyPI

```bash
pip install lupaxa-ssl-expiry
```

### From source (development mode)

```bash
pip install -e ".[dev]"
```

Requires Python 3.13+.

## Library quick start

```python
from lupaxa.ssl_expiry import lookup

result = lookup("example.com", timeout=10.0)
print(result.host, result.status, result.issuer, result.days_remaining)
```

## CLI quick start

```bash
ssl-expiry --help
ssl-expiry example.com example.org
ssl-expiry --file hosts.txt --warn-days 14 --timeout 5
```

You can also run the CLI as a module:

```bash
python -m lupaxa.ssl_expiry --help
python -m lupaxa.ssl_expiry --version
```

## Options

- `HOST`: one or more hostnames
- `--file`, `-f`: text file of hostnames, one per line; `-` reads stdin
- `--timeout`, `-t`: TCP connect and TLS handshake timeout in seconds; default `10`
- `--warn-days`, `-w`: exit `1` when a certificate expires within this many days; default `30`
- `--sort`, `-s`: sort by `host`, `issuer`, `date`, or `days`
- `--order`: `ascending` or `descending` (default `ascending`); requires `--sort`
- `--version`: print the package version

## Documentation

Online documentation:

[Documentation](https://ssl-expiry.thelupaxaproject.org/)

Source repository:

[GitHub](https://github.com/lupaxa-sre-toolbox/ssl-expiry)

### Serve docs locally

From a clone of the repository:

```bash
make mkdocs-serve
```

Then open the local URL printed by MkDocs in your browser.

## Development

Clone the repository and install with Make:

```bash
make init                # first-time makefile-skills checkout
make python-install-dev  # editable install with [dev]
make python-check        # lint, type-check, and test
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
