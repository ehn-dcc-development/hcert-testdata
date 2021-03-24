# Health Certificate Test Data

- `test*` -- test HCERT as raw (bin) and optical (png)

- `issuer*.crt` -- issuer's public key as X.509

- `jwks.json` -- public keys as JWKS
- `jwks_signed.json` -- signed JWKS signed

- `jwks_signer_private.json` -- JWK used to sign `jwks_signed.json`
- `jwks_signer_public.json` -- JWK used to verify `jwks_signed.json`
