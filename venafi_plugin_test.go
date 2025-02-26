//
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

package main

import (
	"context"
	"crypto"
	"flag"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/sigstore/pkg/signature/kms/cliplugin"
)

// This file tests the PluginClient against a pre-built plugin programs.
// It is skipped during normal `go test ./...` invocations. It can be invoked like
// `go test -tags=signer_program -count=1 ./... -key-resource-id [my-kms]://[my-key-ref]`
// See ./README.md for plugin program usage.

// We don't have a TestCryptoSigner since PluginClient.CryptoSigner()'s returned object is meant to be a wrapper around PluginClient.

var (
	inputKeyResourceID = flag.String("key-resource-id", "", "key resource ID for the KMS, defaults to 'venafi://vsign\rsa2048-cert'")
	testHashFunc       = crypto.SHA512
)

// getPluginClient parses the build flags for the KeyResourceID and returns a PluginClient.
func getPluginClient(t *testing.T) *cliplugin.PluginClient {
	t.Helper()
	signerVerifier, err := cliplugin.LoadSignerVerifier(context.Background(), *inputKeyResourceID, testHashFunc)
	if err != nil {
		t.Fatal(err)
	}
	pluginClient := signerVerifier.(*cliplugin.PluginClient)
	return pluginClient
}

// TestDefaultAlgorithm invokes DefaultAlgorithm against the compiled plugin program.
// Since implementations can vary, it merely checks that some non-empty value is returned.
func TestDefaultAlgorithm(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	if defaultAlgorithm := pluginClient.DefaultAlgorithm(); defaultAlgorithm == "" {
		t.Error("expected non-empty default algorithm")
	}
}

// TestSupportedAlgorithms invokes DefaultAlgorithm against the compiled plugin program.
// Since implementations can vary, it merely checks that some non-empty value is returned.
func TestSupportedAlgorithms(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	if supportedAlgorithms := pluginClient.SupportedAlgorithms(); len(supportedAlgorithms) == 0 {
		t.Error("expected non-empty supported algorithms")
	}
}

// TestCreateKey invokes CreateKey against the compiled plugin program.
// Since implementations can vary, it merely checks that some public key is returned.
func TestCreateKey(t *testing.T) {
	pluginClient := getPluginClient(t)
	ctx := context.Background()
	defaultAlgorithm := pluginClient.DefaultAlgorithm()
	fmt.Println("HERE")

	tests := []struct {
		name      string
		algorithm string
		err       error
	}{
		{
			name:      "generate-key-pair not implemented for Venafi CodeSign Protect",
			algorithm: defaultAlgorithm,
			err:       cliplugin.ErrorPluginReturnError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			publicKey, err := pluginClient.CreateKey(ctx, tc.algorithm)

			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}

			if err != nil {
				if diff := cmp.Diff(nil, publicKey, cmpopts.EquateComparable()); diff != "" {
					t.Errorf("expected nil publicKey (-want +got): \n%s", diff)
				}
			} else {
				if publicKey == nil {
					t.Error("unexpected non-nil publicKey")
				}
			}
		})
	}
}

// TestCreateKey invokes SignMessage against the compiled plugin program,
// with combinations of empty or non-empty messages, and digests.
// Since implementations can vary, it merely checks that non-empty signature is returned,
// and that the same signaure can be verified.
/*func TestSignMessageVerifySignature(t *testing.T) {
	t.Parallel()

	pluginClient := getPluginClient(t)

	testMessageBytes := []byte("any message")
	hasher := testHashFunc.New()
	if _, err := hasher.Write(testMessageBytes); err != nil {
		t.Fatal(err)
	}
	testDigest := hasher.Sum(nil)
	testEmptyBytes := []byte(``)
	testBadDigest := []byte("bad digest")
	testBadSignature := []byte("bad signature")

	//ctx := context.Background()
	//defaultAlgorithm := pluginClient.DefaultAlgorithm()

	tests := []struct {
		name    string
		message []byte
		digest  *[]byte
		err     error
	}{
		{
			name:    "message only, no digest",
			message: testMessageBytes,
		},
		{
			name:    "digest only, empty message",
			message: testEmptyBytes,
			digest:  &testDigest,
		},
		{
			name:    "message and digest",
			message: testMessageBytes,
			digest:  &testDigest,
		},
		{
			name:    "failure: bad digest, empty message",
			message: testEmptyBytes,
			digest:  &testBadDigest,
			err:     cliplugin.ErrorPluginReturnError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			signOpts := []signature.SignOption{}
			verifyOpts := []signature.VerifyOption{}
			if tc.digest != nil {
				signOpts = append(signOpts, options.WithDigest(*tc.digest))
				verifyOpts = append(verifyOpts, options.WithDigest(*tc.digest))
			}
			signature, err := pluginClient.SignMessage(bytes.NewReader(tc.message), signOpts...)

			if diff := cmp.Diff(tc.err, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("unexpected error (-want +got): \n%s", diff)
			}
			if err == nil && len(signature) == 0 {
				t.Error("expected non-empty signature")
			}

			if len(signature) > 0 {
				// verify the real signature
				if err = pluginClient.VerifySignature(bytes.NewReader(signature), bytes.NewReader(tc.message), verifyOpts...); err != nil {
					t.Errorf("unexpected error verifying signature: %s", err)
				}
			}
			// verify a fake signature
			if err = pluginClient.VerifySignature(bytes.NewReader(testBadSignature), bytes.NewReader(tc.message), verifyOpts...); err == nil {
				t.Error("expected error verifying fake signature")
			}
		})
	}
}*/
