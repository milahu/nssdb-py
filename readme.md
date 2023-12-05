# nssdb-py

add a `ca.crt` certificate to `$HOME/.pki/nssdb/cert9.db` and `$HOME/.pki/nssdb/key4.db` in python

implement this part of certutil in python:

```
certutil -d sql:$HOME/.pki/nssdb -A -t TC -n "Some Authority" -i ca.crt
```

## related

- https://github.com/nss-dev/nss
  - https://github.com/nss-dev/nss/blob/master/lib/softoken/sdb.c
    - `sdb_init(cert, "nssPublic"`
- https://www.dogtagpki.org/wiki/Support_NSSDB_in_Python_API
  - draft
- https://github.com/drGrove/mtls-cli/blob/main/src/mtls/mtls.py
  - using `certutil`

### parse SSL certificates in python

aka: X.509 certificates

- https://stackoverflow.com/questions/16899247/how-can-i-decode-a-ssl-certificate-using-python
  - https://stackoverflow.com/a/68060835/10440128
    - `import ssl; ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.load_verify_locations("ca.crt"); cert = ctx.get_ca_certs()`
  - https://cryptography.io/en/latest/x509/reference/#loading-certificates
