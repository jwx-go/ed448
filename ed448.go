// Package ed448 provides Ed448 signing, verification, and JWK support for the jwx library.
//
// Ed448 is not included in the main jwx module because Go's standard library
// does not support Ed448, requiring the external github.com/cloudflare/circl
// module. To avoid adding this dependency for all users, Ed448 support is
// provided as a separate module.
//
// To enable Ed448 support, import this package for its side effects:
//
//	import _ "github.com/jwx-go/ed448/v4"
//
// This registers Ed448 signing/verification (via dsig-circl-ed448), JWK key
// import/export, and algorithm-for-key-type mappings. After importing,
// ed448.EdDSAEd448() can be used with jws.Sign, jws.Verify, jwk.Import, etc.
//
// Registration happens in init(). If any underlying jwx Register* call
// returns an error, init() panics — importing this package will crash the
// program at load time. This is the house style across all jwx-go extension
// modules: a failed registration leaves the extension unusable, and
// surfacing it at import time is strictly safer than silently continuing.
//
// # Constructing ed448 keys
//
// Construct ed448 private and public keys via cloudflare/circl's own
// constructors:
//
//   - ed448.GenerateKey(rand.Reader) — fresh random key
//   - ed448.NewKeyFromSeed(seed)     — deterministic from a 57-byte seed
//   - PEM/DER parsers (x509)         — from on-disk material
//
// All of these return correctly-sized values (114-byte private key,
// 57-byte public key).
//
// Do NOT construct ed448 keys via raw type conversion of unvalidated
// bytes:
//
//	bad := ed448.PrivateKey(someBytes)  // unsafe if len(someBytes) != 114
//
// circl's ed448.PrivateKey is a []byte alias, so this conversion is
// always permitted by the type system but produces a value that
// panics on the next call to Sign / Public / Seed when the length is
// wrong. This package's wrappers validate length before calling into
// circl and surface a typed error in that case (so jwk.Import,
// jws.Sign, and jws.Verify cannot crash from a wrong-length raw
// type), but the safer path is to never produce a wrong-length value
// in the first place.
package ed448

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jws/jwsbb"

	// Import dsig-circl-ed448 for side effects: registers Ed448 sign/verify
	// with dsig as a Custom family algorithm.
	_ "github.com/lestrrat-go/dsig-circl-ed448"
)

var eddsaEd448 = jwa.NewSignatureAlgorithm("Ed448")
var ed448Curve = jwa.NewEllipticCurveAlgorithm("Ed448")

// EdDSAEd448 returns the EdDSA Ed448 signature algorithm.
func EdDSAEd448() jwa.SignatureAlgorithm {
	return eddsaEd448
}

// Curve returns the Ed448 elliptic curve algorithm.
func Curve() jwa.EllipticCurveAlgorithm {
	return ed448Curve
}

func init() {
	// Register Ed448 as a known signature algorithm in jwa
	panicOnRegistrationError(jwa.RegisterSignatureAlgorithm(eddsaEd448))

	// Register Ed448 as a known elliptic curve algorithm in jwa
	panicOnRegistrationError(jwa.RegisterEllipticCurveAlgorithm(ed448Curve))

	// Register Ed448 as valid algorithm for OKP key type
	panicOnRegistrationError(jws.RegisterAlgorithmForKeyType(jwa.OKP(), eddsaEd448))

	// Pair the alg with the Ed448 curve so jws.AlgorithmsForKey can
	// narrow inferred algorithms by curve. Without this, an Ed25519
	// jwk.Key would advertise Ed448 in its inferred-algorithm list
	// (and an Ed448 key would advertise the polymorphic EdDSA, which
	// jwx core dispatches as Ed25519 only). Mirrors main jwx's
	// pairing for Ed25519 in jws/jws.go.
	panicOnRegistrationError(jws.RegisterAlgorithmForCurve(ed448Curve, eddsaEd448))

	// Register signer/verifier that handle JWK key unwrapping.
	// The dsig-circl-ed448 signer only accepts raw ed448 keys,
	// so we need this layer to convert JWK keys before dispatch.
	panicOnRegistrationError(jws.RegisterSigner(eddsaEd448, ed448Signer{}))
	panicOnRegistrationError(jws.RegisterVerifier(eddsaEd448, ed448Verifier{}))

	// Register JWK exporter for OKP:Ed448 keys (JWK → raw ed448 key)
	panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("OKP:Ed448"), jwk.KeyExportFunc(exportEd448Key)))

	// Register raw key importer for Ed448 keys
	panicOnRegistrationError(jwk.RegisterOKPRawKeyImporter(jwk.OKPRawKeyImporterFunc(importEd448RawKey)))

	// Register jwk.Import handlers for Ed448 key types (raw ed448 key → JWK)
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[ed448.PublicKey](importEd448PublicKey)))
	panicOnRegistrationError(jwk.RegisterKeyImporter(jwk.KeyImportFunc[ed448.PrivateKey](importEd448PrivateKey)))
}

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/ed448: registration failed: %s", err))
	}
}

// --- Signer/Verifier (JWK key unwrapping) ---

type ed448Signer struct{}

func (ed448Signer) Algorithm() jwa.SignatureAlgorithm { return eddsaEd448 }

func (ed448Signer) Sign(key any, payload []byte) ([]byte, error) {
	var privkey ed448.PrivateKey
	if err := ed448PrivateKey(&privkey, key); err != nil {
		return nil, fmt.Errorf(`ed448.Sign: %w`, err)
	}
	return jwsbb.Sign(privkey, "Ed448", payload, nil)
}

type ed448Verifier struct{}

func (ed448Verifier) Verify(key any, payload, signature []byte) error {
	var pubkey ed448.PublicKey
	if err := ed448PublicKey(&pubkey, key); err != nil {
		return fmt.Errorf(`ed448.Verify: %w`, err)
	}
	return jwsbb.Verify(pubkey, "Ed448", payload, signature)
}

// --- Key conversion ---

// validatePrivateKey checks the length of a circl ed448 private key.
// Misuse: constructing the key via raw type conversion
// `circled448.PrivateKey(bytes)` with len(bytes) != 114 produces a
// value that panics on the next call to Sign / Public / Seed. Every
// circl-supplied constructor (GenerateKey, NewKeyFromSeed, PEM/DER
// parsers) enforces the correct length, so a value reaching us with
// the wrong length is the result of unchecked type conversion at the
// caller. We surface a typed error here so callers see "this key is
// the wrong length" rather than a panic from circl.
func validatePrivateKey(p ed448.PrivateKey) error {
	if len(p) != ed448.PrivateKeySize {
		return fmt.Errorf(`ed448: invalid private key length %d (expected %d). Construct keys via ed448.GenerateKey or ed448.NewKeyFromSeed; raw type conversion of unvalidated bytes is not supported`, len(p), ed448.PrivateKeySize)
	}
	return nil
}

func validatePublicKey(p ed448.PublicKey) error {
	if len(p) != ed448.PublicKeySize {
		return fmt.Errorf(`ed448: invalid public key length %d (expected %d)`, len(p), ed448.PublicKeySize)
	}
	return nil
}

func ed448PrivateKey(dst *ed448.PrivateKey, src any) error {
	if jwkKey, ok := src.(jwk.Key); ok {
		raw, err := jwk.Export[ed448.PrivateKey](jwkKey)
		if err != nil {
			return fmt.Errorf(`failed to produce ed448.PrivateKey from %T: %w`, src, err)
		}
		// jwk.Export goes through exportEd448Key, which validates
		// the seed length and constructs via NewKeyFromSeed — the
		// returned key is always the right length.
		*dst = raw
		return nil
	}

	switch src := src.(type) {
	case ed448.PrivateKey:
		if err := validatePrivateKey(src); err != nil {
			return err
		}
		*dst = src
	case *ed448.PrivateKey:
		if err := validatePrivateKey(*src); err != nil {
			return err
		}
		*dst = *src
	default:
		return fmt.Errorf(`expected ed448.PrivateKey, got %T`, src)
	}
	return nil
}

func ed448PublicKey(dst *ed448.PublicKey, src any) error {
	if jwkKey, ok := src.(jwk.Key); ok {
		pk, err := jwk.PublicRawKeyOf(jwkKey)
		if err != nil {
			return fmt.Errorf(`failed to produce public key from %T: %w`, src, err)
		}
		src = pk
	}

	// Validate any private key BEFORE calling Public() — circl's
	// PrivateKey.Public() does priv[SeedSize:] which out-of-range
	// panics on a slice shorter than 57 bytes.
	switch key := src.(type) {
	case ed448.PrivateKey:
		if err := validatePrivateKey(key); err != nil {
			return err
		}
		src = key.Public()
	case *ed448.PrivateKey:
		if err := validatePrivateKey(*key); err != nil {
			return err
		}
		src = key.Public()
	}

	switch src := src.(type) {
	case ed448.PublicKey:
		if err := validatePublicKey(src); err != nil {
			return err
		}
		*dst = src
	case *ed448.PublicKey:
		if err := validatePublicKey(*src); err != nil {
			return err
		}
		*dst = *src
	default:
		return fmt.Errorf(`expected ed448.PublicKey, got %T`, src)
	}
	return nil
}

// --- JWK key export (JWK → raw ed448 key) ---

func exportEd448Key(key jwk.Key, _ any) (any, error) {
	switch key := key.(type) {
	case jwk.OKPPrivateKey:
		x, ok := key.X()
		if !ok {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		d, ok := key.D()
		if !ok {
			return nil, fmt.Errorf(`missing "d" field`)
		}
		if len(d) != ed448.SeedSize {
			return nil, fmt.Errorf(`ed448: wrong private key seed size %d (expected %d)`, len(d), ed448.SeedSize)
		}
		ret := ed448.NewKeyFromSeed(d)
		pub := ret.Public().(ed448.PublicKey) //nolint:forcetypeassert
		// Both operands are public material — x is the JWK public component and
		// pub is derived from d via NewKeyFromSeed; constant-time comparison is
		// not required.
		if !bytes.Equal(x, pub) {
			return nil, fmt.Errorf(`ed448: invalid x value given d value`)
		}
		return ret, nil
	case jwk.OKPPublicKey:
		x, ok := key.X()
		if !ok {
			return nil, fmt.Errorf(`missing "x" field`)
		}
		if len(x) != ed448.PublicKeySize {
			return nil, fmt.Errorf(`ed448: wrong public key size %d (expected %d)`, len(x), ed448.PublicKeySize)
		}
		return ed448.PublicKey(x), nil
	default:
		return nil, jwk.ContinueError()
	}
}

// --- JWK raw key import ---

func importEd448RawKey(key any) (jwa.EllipticCurveAlgorithm, []byte, []byte, bool) {
	switch k := key.(type) {
	case ed448.PublicKey:
		// Wrong-length values are not valid ed448 keys; signal "not
		// for me" so jwk's importer chain falls through cleanly
		// instead of crashing inside circl below.
		if len(k) != ed448.PublicKeySize {
			return jwa.InvalidEllipticCurve(), nil, nil, false
		}
		return ed448Curve, []byte(k), nil, true
	case ed448.PrivateKey:
		if len(k) != ed448.PrivateKeySize {
			return jwa.InvalidEllipticCurve(), nil, nil, false
		}
		pub := k.Public().(ed448.PublicKey) //nolint:forcetypeassert
		return ed448Curve, []byte(pub), k.Seed(), true
	}
	return jwa.InvalidEllipticCurve(), nil, nil, false
}

func importEd448PrivateKey(src ed448.PrivateKey) (jwk.Key, error) {
	if err := validatePrivateKey(src); err != nil {
		return nil, err
	}
	key, err := jwkunsafe.NewKey(jwa.OKP())
	if err != nil {
		return nil, fmt.Errorf(`failed to create OKP private key: %w`, err)
	}
	pub := src.Public().(ed448.PublicKey) //nolint:forcetypeassert
	if err := key.Set(jwk.OKPCrvKey, ed448Curve); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.OKPXKey, []byte(pub)); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.OKPDKey, src.Seed()); err != nil {
		return nil, err
	}
	return key, nil
}

func importEd448PublicKey(src ed448.PublicKey) (jwk.Key, error) {
	if err := validatePublicKey(src); err != nil {
		return nil, err
	}
	key, err := jwkunsafe.NewPublicKey(jwa.OKP())
	if err != nil {
		return nil, fmt.Errorf(`failed to create OKP public key: %w`, err)
	}
	if err := key.Set(jwk.OKPCrvKey, ed448Curve); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.OKPXKey, []byte(src)); err != nil {
		return nil, err
	}
	return key, nil
}
