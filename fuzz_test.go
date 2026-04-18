package ed448_test

import (
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"

	jwxed448 "github.com/jwx-go/ed448/v4"
)

func FuzzSignAndVerify(f *testing.F) {
	f.Add([]byte("Hello, World!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))
	f.Add([]byte("The true sign of intelligence is not knowledge but imagination."))

	pk, sk, err := ed448.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, payload []byte) {
		signed, err := jws.Sign(payload, jws.WithKey(jwxed448.EdDSAEd448(), sk))
		require.NoError(t, err)

		verified, err := jws.Verify(signed, jws.WithKey(jwxed448.EdDSAEd448(), pk))
		require.NoError(t, err)
		require.Equal(t, payload, verified)
	})
}

func FuzzJWKRoundTrip(f *testing.F) {
	_, sk, err := ed448.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}
	jwkKey, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		f.Fatal(err)
	}
	seedJSON, err := json.Marshal(jwkKey)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(seedJSON)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKeyAs[jwk.Key](data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKeyAs[jwk.Key](buf)
	})
}
