# Examples

## One Host

```bash
ssl-expiry example.com
```

## Several Hosts

```bash
ssl-expiry example.com example.org example.net
```

## A List on Disk

`hosts.txt`:

```text
# production
example.com
example.org
```

```bash
ssl-expiry --file hosts.txt --warn-days 14
```

## Hosts from Another Command

```bash
printf '%s\n' example.com example.org | ssl-expiry --file -
```

## Sorted Table

```bash
ssl-expiry --sort days --order descending example.com example.org example.net
```

## Shorter Timeout

```bash
ssl-expiry example.com --timeout 5
```

## Library

```python
from datetime import UTC, datetime

from lupaxa.ssl_expiry import lookup

result = lookup("example.com", timeout=5.0, now=datetime.now(UTC))
print(result.host, result.issuer, result.status, result.days_remaining)
```
