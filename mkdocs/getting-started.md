# Getting started

## Requirements

- Python 3.13 or newer
- Outbound TCP access to port 443 for the hosts you check
- The `cryptography` and `prettytable` packages, installed with this distribution

## Install

```bash
pip install lupaxa-ssl-expiry
ssl-expiry --help
```

## First run

```bash
ssl-expiry example.com example.org
```

Every host is a row in the table. A date further out than `--warn-days`
(default 30) is a quiet success and exits `0`. A certificate that is due
sooner, already expired, or an invalid host makes the command exit `1`. A
failed connection exits `2`.

Module entry point:

```bash
python -m lupaxa.ssl_expiry --version
```

### From source (development)

```bash
make init
make python-install-dev
ssl-expiry --version
```

## Makefile helpers

```bash
make python-check
make mkdocs-serve
```
