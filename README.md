# github.com/jwx-go/ed448/v4 [![Go Reference](https://pkg.go.dev/badge/github.com/jwx-go/ed448/v4.svg)](https://pkg.go.dev/github.com/jwx-go/ed448/v4)

Ed448 signing/verification and JWK support for [github.com/lestrrat-go/jwx/v4](https://github.com/lestrrat-go/jwx), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

This is a companion module to `github.com/lestrrat-go/jwx/v4` and has no stability guarantees of its own. Its API may change without notice to track changes in `github.com/lestrrat-go/jwx/v4`.

# Why a separate module?

Go's standard library does not include Ed448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `jwx` user to pull in `circl`, Ed448 support is provided as an opt-in companion module.

# Installation

```
go get github.com/jwx-go/ed448/v4
```

# Constructing ed448 keys

Use cloudflare/circl's own constructors:

- `ed448.GenerateKey(rand.Reader)` — fresh random key
- `ed448.NewKeyFromSeed(seed)` — deterministic from a 57-byte seed
- PEM/DER parsers — from on-disk material

These all return correctly-sized values (114-byte private key, 57-byte public key).

**Do not** construct ed448 keys via raw type conversion of unvalidated bytes:

```go
bad := ed448.PrivateKey(someBytes) // unsafe if len(someBytes) != 114
```

`circl`'s `ed448.PrivateKey` is a `[]byte` alias, so this conversion is always permitted by the type system but produces a value that panics on the next call to `Sign` / `Public` / `Seed` when the length is wrong. This package's wrappers validate length before calling into circl and surface a typed error for the wrong-length case (so `jwk.Import`, `jws.Sign`, and `jws.Verify` cannot crash from a wrong-length raw type), but the safer path is to never produce a wrong-length value in the first place.
