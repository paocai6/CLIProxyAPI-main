// Package tlsspec provides custom uTLS ClientHelloSpec definitions for TLS
// fingerprint mimicry. These specs are shared between the executor and auth
// packages to ensure consistent TLS behavior across all Anthropic API requests.
package tlsspec

import (
	tls "github.com/refraction-networking/utls"
)

// Ed25519 and Ed448 signature schemes are not exported by uTLS as named
// constants. These values are defined in the IANA TLS SignatureScheme registry.
const (
	signatureEd25519 tls.SignatureScheme = 0x0809
	signatureEd448   tls.SignatureScheme = 0x080a
)

// NodeJS returns a ClientHelloSpec matching Node.js 20+ with OpenSSL 3.x.
//
// This produces a JA3/JA4 fingerprint consistent with a real Node.js process,
// which is what Claude Code (claude-cli) uses internally. Key differences from
// Chrome's fingerprint:
//   - No GREASE values in cipher suites or extensions
//   - No post-quantum key shares (X25519 only, no Kyber/ML-KEM)
//   - No compress_certificate (Brotli) extension
//   - No application_settings (ALPS) extension
//   - Simpler extension set with OpenSSL default ordering
//
// Extension order validated against Node.js v20.11.0 / OpenSSL 3.0.13.
func NodeJS() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMin: tls.VersionTLS12,
		TLSVersMax: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (OpenSSL 3.x default order)
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,

			// TLS 1.2 ECDHE cipher suites (OpenSSL 3.x default preference order)
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// TLS 1.2 CBC fallbacks (present in OpenSSL default list for compatibility)
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []uint8{0}, // No compression
		Extensions: []tls.TLSExtension{
			// Extension order follows OpenSSL 3.x default (Node.js inherits this).
			// SNIExtension{} is populated automatically by ApplyPreset from tlsConfig.ServerName.
			&tls.SNIExtension{},
			&tls.SupportedPointsExtension{
				SupportedPoints: []byte{0}, // uncompressed
			},
			&tls.SupportedCurvesExtension{
				Curves: []tls.CurveID{
					tls.X25519,    // 0x001d
					tls.CurveP256, // 0x0017
					tls.CurveP384, // 0x0018
				},
			},
			&tls.SessionTicketExtension{},
			&tls.ExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithP521AndSHA512,
					signatureEd25519,
					signatureEd448,
					tls.PSSWithSHA256,
					tls.PSSWithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA256,
					tls.PKCS1WithSHA384,
					tls.PKCS1WithSHA512,
				},
			},
			&tls.ALPNExtension{
				AlpnProtocols: []string{"h2", "http/1.1"},
			},
			&tls.StatusRequestExtension{},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{
				KeyShares: []tls.KeyShare{
					{Group: tls.X25519},
				},
			},
			&tls.SupportedVersionsExtension{
				Versions: []uint16{
					tls.VersionTLS13,
					tls.VersionTLS12,
				},
			},
			&tls.PSKKeyExchangeModesExtension{
				Modes: []uint8{tls.PskModeDHE}, // psk_dhe_ke
			},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}
}
