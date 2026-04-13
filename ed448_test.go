package ed448_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"testing"

	circled448 "github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	jwxed448 "github.com/jwx-go/ed448/v4"
)

// TestRegistration verifies that importing the ed448 package registers
// the algorithm and curve constants with jwa, and that the accessor
// functions return the correct values.
func TestRegistration(t *testing.T) {
	t.Run("EdDSAEd448 accessor returns Ed448 signature algorithm", func(t *testing.T) {
		alg := jwxed448.EdDSAEd448()
		require.Equal(t, "Ed448", alg.String())
	})

	t.Run("Curve accessor returns Ed448 elliptic curve", func(t *testing.T) {
		crv := jwxed448.Curve()
		require.Equal(t, "Ed448", crv.String())
	})

	t.Run("LookupSignatureAlgorithm finds Ed448", func(t *testing.T) {
		alg, ok := jwa.LookupSignatureAlgorithm("Ed448")
		require.True(t, ok, `Ed448 should be registered as a signature algorithm`)
		require.Equal(t, jwxed448.EdDSAEd448(), alg)
	})

	t.Run("LookupEllipticCurveAlgorithm finds Ed448", func(t *testing.T) {
		crv, ok := jwa.LookupEllipticCurveAlgorithm("Ed448")
		require.True(t, ok, `Ed448 should be registered as an elliptic curve`)
		require.Equal(t, jwxed448.Curve(), crv)
	})
}

// TestSignVerifyRoundTrip covers the signer/verifier glue with both raw
// ed448 keys and jwk-wrapped keys, exercising the ed448PrivateKey /
// ed448PublicKey conversion paths.
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := circled448.GenerateKey(rand.Reader)
	require.NoError(t, err, `ed448.GenerateKey should succeed`)

	payload := []byte(`Lorem ipsum`)

	t.Run("raw private key sign, raw public key verify", func(t *testing.T) {
		signed, err := jws.Sign(payload, jws.WithKey(jwxed448.EdDSAEd448(), priv))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxed448.EdDSAEd448(), pub))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})

	t.Run("raw private key sign, raw private key verify (public derived)", func(t *testing.T) {
		// ed448Verifier should unwrap a private key to its public half.
		signed, err := jws.Sign(payload, jws.WithKey(jwxed448.EdDSAEd448(), priv))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxed448.EdDSAEd448(), priv))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})

	t.Run("jwk private key sign, jwk public key verify", func(t *testing.T) {
		jwkPriv, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err, `jwk.Import raw private should produce jwk`)

		jwkPub, err := jwk.Import[jwk.Key](pub)
		require.NoError(t, err, `jwk.Import raw public should produce jwk`)

		signed, err := jws.Sign(payload, jws.WithKey(jwxed448.EdDSAEd448(), jwkPriv))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxed448.EdDSAEd448(), jwkPub))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})

	t.Run("tampered signature is rejected", func(t *testing.T) {
		signed, err := jws.Sign(payload, jws.WithKey(jwxed448.EdDSAEd448(), priv))
		require.NoError(t, err)

		// Flip a byte in the signature portion (the last segment).
		tampered := bytes.Clone(signed)
		tampered[len(tampered)-5] ^= 0x01

		_, err = jws.Verify(tampered, jws.WithKey(jwxed448.EdDSAEd448(), pub))
		require.Error(t, err, `jws.Verify should reject tampered signature`)
	})
}

// TestJWKRoundTrip covers the four jwk import/export paths:
// raw private → jwk, raw public → jwk, jwk private → raw, jwk public → raw.
func TestJWKRoundTrip(t *testing.T) {
	pub, priv, err := circled448.GenerateKey(rand.Reader)
	require.NoError(t, err)

	t.Run("private key round-trip", func(t *testing.T) {
		jwkKey, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)

		// Re-export to raw.
		raw, err := jwk.Export[circled448.PrivateKey](jwkKey)
		require.NoError(t, err)
		require.Equal(t, []byte(priv), []byte(raw),
			`raw → jwk → raw should preserve the private key bytes`)
	})

	t.Run("public key round-trip", func(t *testing.T) {
		jwkKey, err := jwk.Import[jwk.Key](pub)
		require.NoError(t, err)

		raw, err := jwk.Export[circled448.PublicKey](jwkKey)
		require.NoError(t, err)
		require.Equal(t, []byte(pub), []byte(raw),
			`raw → jwk → raw should preserve the public key bytes`)
	})

	t.Run("jwk JSON serialization round-trip", func(t *testing.T) {
		jwkKey, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)

		serialized, err := json.Marshal(jwkKey)
		require.NoError(t, err)

		parsed, err := jwk.ParseKey[jwk.Key](serialized)
		require.NoError(t, err)

		raw, err := jwk.Export[circled448.PrivateKey](parsed)
		require.NoError(t, err)
		require.Equal(t, []byte(priv), []byte(raw))
	})

	t.Run("public key derived from private matches raw public", func(t *testing.T) {
		jwkPriv, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)

		pubOnly, err := jwk.PublicKeyOf(jwkPriv)
		require.NoError(t, err)

		rawPub, err := jwk.Export[circled448.PublicKey](pubOnly)
		require.NoError(t, err)
		require.Equal(t, []byte(pub), []byte(rawPub))
	})
}

// TestJWKErrorCases covers error paths in the JWK export function.
func TestJWKErrorCases(t *testing.T) {
	t.Run("private key with wrong seed size rejected", func(t *testing.T) {
		// Build a JWK with a valid x but a truncated d. We round-trip
		// through JSON to construct the malformed key since the Go
		// struct accessors enforce shape.
		pub, priv, err := circled448.GenerateKey(rand.Reader)
		require.NoError(t, err)

		good, err := jwk.Import[jwk.Key](priv)
		require.NoError(t, err)
		serialized, err := json.Marshal(good)
		require.NoError(t, err)

		// Replace d with a 32-byte (too-short) seed.
		var raw map[string]any
		require.NoError(t, json.Unmarshal(serialized, &raw))
		raw["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 bytes b64url
		truncated, err := json.Marshal(raw)
		require.NoError(t, err)

		bad, err := jwk.ParseKey[jwk.Key](truncated)
		require.NoError(t, err, `parse should succeed; only export should fail`)

		_, err = jwk.Export[circled448.PrivateKey](bad)
		require.Error(t, err, `export of truncated d should fail`)
		_ = pub
	})

	t.Run("public key with wrong x size rejected", func(t *testing.T) {
		raw := map[string]any{
			"kty": "OKP",
			"crv": "Ed448",
			"x":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // too short
		}
		serialized, err := json.Marshal(raw)
		require.NoError(t, err)

		bad, err := jwk.ParseKey[jwk.Key](serialized)
		require.NoError(t, err, `parse should succeed`)

		_, err = jwk.Export[circled448.PublicKey](bad)
		require.Error(t, err, `export of truncated x should fail`)
	})

	t.Run("private key with mismatched x rejected", func(t *testing.T) {
		pub1, priv1, err := circled448.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pub2, _, err := circled448.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// Build a JWK with priv1's d but pub2's x.
		jwkPriv, err := jwk.Import[jwk.Key](priv1)
		require.NoError(t, err)

		serialized, err := json.Marshal(jwkPriv)
		require.NoError(t, err)

		var raw map[string]any
		require.NoError(t, json.Unmarshal(serialized, &raw))
		// Replace x with pub2's bytes encoded as base64url-nopad.
		jwkPub2, err := jwk.Import[jwk.Key](pub2)
		require.NoError(t, err)
		jwkPub2Bytes, err := json.Marshal(jwkPub2)
		require.NoError(t, err)
		var pub2Raw map[string]any
		require.NoError(t, json.Unmarshal(jwkPub2Bytes, &pub2Raw))
		raw["x"] = pub2Raw["x"]

		tampered, err := json.Marshal(raw)
		require.NoError(t, err)

		bad, err := jwk.ParseKey[jwk.Key](tampered)
		require.NoError(t, err, `parse should succeed`)

		_, err = jwk.Export[circled448.PrivateKey](bad)
		require.Error(t, err, `export should detect x/d mismatch`)
		_ = pub1
	})

	t.Run("malformed JSON rejected by ParseKey", func(t *testing.T) {
		_, err := jwk.ParseKey[jwk.Key]([]byte(`{not json`))
		require.Error(t, err)
	})

	t.Run("wrong curve rejected by Export", func(t *testing.T) {
		raw := map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
		}
		serialized, err := json.Marshal(raw)
		require.NoError(t, err)

		k, err := jwk.ParseKey[jwk.Key](serialized)
		require.NoError(t, err)

		_, err = jwk.Export[circled448.PublicKey](k)
		require.Error(t, err, `Ed25519 key should not export as ed448`)
	})
}
