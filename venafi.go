// Copyright 2024 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main implements fake signer to be used in tests
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/sigstore/pkg/signature"
	c "github.com/venafi/vsign/pkg/crypto"
	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
)

const (
	defaultAlgorithm = "rsa-2048"
)

var (
	supportedAlgorithms = []string{defaultAlgorithm}
)

// VenafiSignerVerifier creates and verifies digital signatures with a key saved at KeyResourceID,
// and implements signerverifier.SignerVerifier.
type VenafiSignerVerifier struct {
	keyResourceID string
	hashFunc      crypto.Hash
}

// DefaultAlgorithm returns the default algorithm for the signer.
func (i VenafiSignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

// SupportedAlgorithms returns the supported algorithms for the signer.
func (i VenafiSignerVerifier) SupportedAlgorithms() []string {
	return supportedAlgorithms
}

// Not currently implemented for Venafi CodeSign Protect
func (i VenafiSignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return nil, fmt.Errorf("generate-key-pair not implemented for Venafi CodeSign Protect")
}

// PublicKey returns the public key.
func (i VenafiSignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return loadPublicKey(i.keyResourceID)
}

// SignMessage signs the message with the KeyResourceID.
func (i VenafiSignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	os.Setenv("VSIGN_PROJECT", "placeholder")
	os.Setenv("VSIGN_KEY_LABEL", "placeholder")
	vSignCfg, err := vsign.BuildConfig(context.Background(), "")

	if err != nil {
		return nil, fmt.Errorf("error building config: %v", err)
	}

	_, present := os.LookupEnv("VSIGN_APIKEY")

	if present {
		vSignCfg.KeyLabel = i.keyResourceID
	} else {
		vSignCfg.Project = i.keyResourceID
	}

	connector, err := vsign.NewClient(&vSignCfg)

	if err != nil {
		return nil, fmt.Errorf("unable to connect to %s: %s", vSignCfg.ConnectorType, err)
	}

	e, err := connector.GetEnvironment()
	if err != nil {
		return nil, fmt.Errorf("unable to get environment: %s", err)
	}

	data, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("error reading message: %s", err)
	}

	var mech = 0

	if !present {
		certs, err := c.ParseCertificates(e.CertificateChainData)
		if err != nil {
			return nil, fmt.Errorf("error loading certificate: %s", err)
		}
		mech = signingAlgToMech(certs[0])
	} else {
		mech = c.RsaPkcs
	}

	sig, err := connector.Sign(&endpoint.SignOption{
		KeyID:     e.KeyID,
		Mechanism: mech,
		DigestAlg: getDigestAlg(i.hashFunc),
		Payload:   []byte(base64.StdEncoding.EncodeToString(data)),
		B64Flag:   true,
		RawFlag:   false,
	})

	if err != nil {
		return nil, fmt.Errorf("unable to sign: %s", err)
	}

	return sig, nil
}

// VerifySignature verifies the signature.
func (i VenafiSignerVerifier) VerifySignature(signature io.Reader, message io.Reader, opts ...signature.VerifyOption) error {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	publicKey, err := loadPublicKey(i.keyResourceID)
	if err != nil {
		return fmt.Errorf("error loading public key: %w", err)
	}
	var digest []byte
	var signerOpts crypto.SignerOpts = i.hashFunc
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	if len(digest) == 0 {
		digest, err = computeDigest(&message, signerOpts.HashFunc())
		if err != nil {
			return err
		}
	}

	sig, err := io.ReadAll(signature)
	if err != nil {
		return fmt.Errorf("error reading signature: %w", err)
	}

	msg, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("error reading message: %w", err)
	}

	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, signerOpts.HashFunc(), digest, sig); err != nil {
			return fmt.Errorf("error verifying signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey, digest, sig) {
			return fmt.Errorf("failed verification")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey, msg, sig) {
			return fmt.Errorf("failed verification")
		}
	default:
		if err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), signerOpts.HashFunc(), digest, sig); err != nil {
			return fmt.Errorf("error verifying signature: %w", err)
		}
	}

	return nil
}

// CryptoSigner need not be fully implemented by plugins.
func (i VenafiSignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	panic("CryptoSigner() not implemented")
}

func loadPublicKey(keyResourceID string) (crypto.PublicKey, error) {
	os.Setenv("VSIGN_PROJECT", "placeholder")
	os.Setenv("VSIGN_KEY_LABEL", "placeholder")
	vSignCfg, err := vsign.BuildConfig(context.Background(), "")

	if err != nil {
		return nil, fmt.Errorf("error building config")
	}

	_, present := os.LookupEnv("VSIGN_APIKEY")

	if present {
		vSignCfg.KeyLabel = keyResourceID
	} else {
		vSignCfg.Project = keyResourceID
	}

	connector, err := vsign.NewClient(&vSignCfg)

	if err != nil {
		return nil, fmt.Errorf("unable to connect to %s: %s", vSignCfg.ConnectorType, err)
	}

	e, err := connector.GetEnvironment()
	if err != nil {
		return nil, fmt.Errorf("unable to get environment: %s", err)
	}

	if e.CertificateChainData != nil {
		certs, err := c.ParseCertificates(e.CertificateChainData)
		if err != nil {
			return nil, fmt.Errorf("unable to parse x.509 certificates %s", err)
		}
		return certs[0].PublicKey, nil
	} else {
		return e.PublicKey, nil
	}

}

// computeDigest computes the message digest with the hash function.
func computeDigest(message *io.Reader, hashFunc crypto.Hash) ([]byte, error) {
	hasher := hashFunc.New()
	if _, err := io.Copy(hasher, *message); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func signingAlgToMech(cert *x509.Certificate) int {
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return c.EcDsa
	case *rsa.PublicKey:
		return c.RsaPkcs
	default:
		return 0
	}
}

func getDigestAlg(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	case crypto.SHA1:
		return "sha1"
	default:
		return "sha256"
	}
}
