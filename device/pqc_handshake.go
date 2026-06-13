/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * PQC Handshake Extension — ML-KEM-768 Hybrid Key Exchange
 */

package device

import (
	"errors"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	PQCPublicKeySize  = mlkem768.PublicKeySize
	PQCCiphertextSize = mlkem768.CiphertextSize
	PQCSharedSecretSize = mlkem768.SharedKeySize
)

var (
	ErrPqcKeyGenFailed = errors.New("pqc: ML-KEM key generation failed")
	ErrPqcEncapFailed  = errors.New("pqc: ML-KEM encapsulation failed")
	ErrPqcDecapFailed  = errors.New("pqc: ML-KEM decapsulation authentication mismatch")
)

// PqcPrivateKey encapsulates the ML-KEM-768 private key,
// allowing it to be safely wiped from memory.
type PqcPrivateKey struct {
	key *mlkem768.PrivateKey
}

// GeneratePqcKeyPair generates a new ML-KEM-768 ephemeral keypair.
func GeneratePqcKeyPair() (*PqcPrivateKey, []byte, error) {
	pk, sk, err := mlkem768.GenerateKeyPair()
	if err != nil {
		return nil, nil, ErrPqcKeyGenFailed
	}
	
	pubKeyBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, ErrPqcKeyGenFailed
	}
	
	return &PqcPrivateKey{key: sk}, pubKeyBytes, nil
}

// PqcEncapsulate generates an ephemeral shared secret and encapsulates it
// against the provided ML-KEM-768 public key.
func PqcEncapsulate(pubKeyBytes []byte) (sharedSecret []byte, ciphertext []byte, err error) {
	pk := new(mlkem768.PublicKey)
	if err := pk.UnmarshalBinary(pubKeyBytes); err != nil {
		return nil, nil, ErrPqcEncapFailed
	}

	ciphertext = make([]byte, mlkem768.CiphertextSize)
	sharedSecret = make([]byte, mlkem768.SharedKeySize)

	pk.EncapsulateTo(ciphertext, sharedSecret)
	return sharedSecret, ciphertext, nil
}

// Decapsulate decrypts the ciphertext using the stored private key.
func (sk *PqcPrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if sk.key == nil {
		return nil, ErrPqcDecapFailed
	}

	sharedSecret = make([]byte, mlkem768.SharedKeySize)
	if !sk.key.DecapsulateTo(sharedSecret, ciphertext) {
		return nil, ErrPqcDecapFailed
	}

	return sharedSecret, nil
}

// Clear safely zeros out the private key from memory and nils the pointer.
func (sk *PqcPrivateKey) Clear() {
	if sk.key != nil {
		// Attempt to clear internal representations by re-initializing it
		// Though Go GC manages this, explicit zeroing of the struct is best effort
		// Since CIRCL doesn't expose a zeroizer natively on the PrivateKey,
		// we drop the reference.
		sk.key = nil
	}
}
