# PKCS#12 weak-cipher fixtures

The files in this directory contain a generated, self-signed test certificate
and its non-secret test-only RSA private key. They exercise the two PBE
implementations supported by `golang.org/x/crypto/pkcs12`:

| File | Key-bag PBE algorithm | SHA-256 |
|---|---|---|
| `pbe-rc2.p12` | `pbeWithSHA1And40BitRC2-CBC` | `5a2e09ac1899cf7844b494c859de971d2607062032ceb2508003e0c8459ef02b` |
| `pbe-tripledes.p12` | `pbeWithSHA1And3-KeyTripleDES-CBC` | `451d6a4e5eb2fcdcf5059ff7d5b0b6689486d485c28fa297a41a402737c7e6de` |

Both fixtures use the password `testpass`. Their certificate bags are left
unencrypted so decoding each fixture selects exactly one PBE implementation.
Tests can consequently observe one PBE report and one underlying-cipher report
without unrelated PKCS#12 operations.

They were generated with OpenSSL 3.6.3:

```sh
openssl genrsa -out test-key.pem 2048
openssl req -new -x509 -key test-key.pem -out test-cert.pem -days 1 \
  -subj /CN=testcert

openssl pkcs12 -export -in test-cert.pem -inkey test-key.pem \
  -out pbe-rc2.p12 -keypbe PBE-SHA1-RC2-40 -certpbe NONE \
  -passout pass:testpass -macalg sha1 -name "Single PBE-SHA1-RC2-40" \
  -provider legacy -provider default

openssl pkcs12 -export -in test-cert.pem -inkey test-key.pem \
  -out pbe-tripledes.p12 -keypbe PBE-SHA1-3DES -certpbe NONE \
  -passout pass:testpass -macalg sha1 -name "Single PBE-SHA1-3DES" \
  -provider legacy -provider default
```
