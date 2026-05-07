# Ed448 Extension for JWX

## Overview

This module (`github.com/jwx-go/ed448/v4`) provides Ed448 signing, verification, and JWK support for `github.com/lestrrat-go/jwx`.

Ed448 is not included in the main jwx module because Go's standard library does not support Ed448, requiring the external `github.com/cloudflare/circl` module. To avoid adding this dependency for all users, Ed448 support is provided as a separate extension module.

To enable Ed448 support, import this package for its side effects:

```go
import _ "github.com/jwx-go/ed448/v4"
```

## Architecture

This module registers the Ed448 curve and EdDSA-Ed448 signature algorithm via jwx's extension point system. Ed448 uses the OKP key type (`jwa.OKP()`) with the `Ed448` curve. The module bridges `github.com/cloudflare/circl/sign/ed448` into jwx through `dsig-circl-ed448`, registering custom JWK key import/export handlers and JWS signer/verifier implementations that unwrap JWK keys before delegating to the underlying circl implementation.

### Registration Points

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwa` | `RegisterSignatureAlgorithm()` | Register EdDSA-Ed448 |
| `jwa` | `RegisterEllipticCurveAlgorithm()` | Register Ed448 curve |
| `jws` | `RegisterAlgorithmForKeyType()` | Associate Ed448 with OKP key type |
| `jws` | `RegisterAlgorithmForCurve()` | Scope Ed448 to OKP keys with curve=Ed448 (so AlgorithmsForKey narrows inferred algs by curve) |
| `jws` | `RegisterSigner()` | Ed448 signing (unwrap JWK, delegate to jwsbb) |
| `jws` | `RegisterVerifier()` | Ed448 verification (unwrap JWK, delegate to jwsbb) |
| `jwk` | `RegisterKeyExporter()` | Convert JWK OKP:Ed448 keys to raw ed448 keys |
| `jwk` | `RegisterOKPRawKeyImporter()` | Convert raw ed448 keys to OKP JWK fields |
| `jwk` | `RegisterKeyImporter()` | Convert `ed448.PublicKey`/`ed448.PrivateKey` to `jwk.Key` |

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `ed448.go` | Package doc, algorithm constants, `init()` registration, signer/verifier, key import/export |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
