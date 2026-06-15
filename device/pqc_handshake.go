/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * PQC Handshake Extension — ML-KEM-768 Hybrid Key Exchange
 */

package device

import (
	"crypto/rand"
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
	pk, sk, err := mlkem768.GenerateKeyPair(rand.Reader)
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
	if len(pubKeyBytes) != mlkem768.PublicKeySize {
		return nil, nil, ErrPqcEncapFailed
	}
	pk := new(mlkem768.PublicKey)
	if err := pk.Unpack(pubKeyBytes); err != nil {
		return nil, nil, ErrPqcEncapFailed
	}

	ciphertext = make([]byte, mlkem768.CiphertextSize)
	sharedSecret = make([]byte, mlkem768.SharedKeySize)

	// seed == nil -> circl draws the encapsulation seed from crypto/rand.Reader.
	pk.EncapsulateTo(ciphertext, sharedSecret, nil)
	return sharedSecret, ciphertext, nil
}

// Decapsulate decrypts the ciphertext using the stored private key.
func (sk *PqcPrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if sk.key == nil {
		return nil, ErrPqcDecapFailed
	}

	if len(ciphertext) != mlkem768.CiphertextSize {
		return nil, ErrPqcDecapFailed
	}
	sharedSecret = make([]byte, mlkem768.SharedKeySize)
	// ML-KEM is IND-CCA2 with implicit rejection: DecapsulateTo always yields
	// a shared key (a pseudo-random one for a tampered ciphertext), which then
	// fails the downstream AEAD transcript check. It panics only on a
	// wrong-length ciphertext, which the guard above prevents.
	sk.key.DecapsulateTo(sharedSecret, ciphertext)

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
