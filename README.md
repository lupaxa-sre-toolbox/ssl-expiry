<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="SRE Toolbox" />
  </a>
</p>

<h1 align="center">SSL Expiry</h1>

Check TLS certificate expiration dates on port 443.

## Install

```bash
pip install lupaxa-ssl-expiry
ssl-expiry --help
```

## CLI

```bash
ssl-expiry example.com example.org
ssl-expiry --file hosts.txt --warn-days 14
python -m lupaxa.ssl_expiry --version
```

Results print as a table with host, issuer, date, and days columns. Every
host is a row, including invalid hosts and connection failures. The issuer
is the certificate's organization name, or its common name when the
organization is absent. The command exits `1` when a certificate expires
within `--warn-days` (default 30), is already expired, or the host is
invalid. `--sort host`, `--sort issuer`, `--sort date`, or `--sort days`
orders the table. `--order descending` reverses that order.

## Library

```python
from lupaxa.ssl_expiry import lookup

result = lookup("example.com")
print(result.status, result.issuer, result.expiration, result.days_remaining)
```

## Development

```bash
make init
make python-install-dev
make python-check
make mkdocs-serve
```

## Documentation

The published guide is at
<https://ssl-expiry.thelupaxaproject.org/>.

Site Markdown lives in `mkdocs/`.

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
