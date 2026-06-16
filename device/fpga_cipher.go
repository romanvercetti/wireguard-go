/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2025 ENQUANTUM. All Rights Reserved.
 *
 * fpga_cipher.go
 *
 * cgo bridge from the wireguard-go transport data path to the ENQ-OS FPGA
 * AEAD hardware offload library (libenq_aead). The Alveo U200 / OpenNIC
 * shell exposes the ENQUANTUM AEAD IP core over Xilinx QDMA character
 * devices (/dev/qdma_h2c_0, /dev/qdma_c2h_0); libenq_aead abstracts that
 * streaming PCIe interface into the two blocking primitives wrapped here:
 *
 *   FpgaAeadEncrypt -> C.fpga_aead_encrypt  (TX path, RoutineEncryption)
 *   FpgaAeadDecrypt -> C.fpga_aead_decrypt  (RX path, RoutineDecryption)
 *
 * Concurrency: these wrappers add NO locking. The encryption/decryption
 * worker goroutines call them directly; the C library serialises the QDMA
 * pipeline internally via its own POSIX mutexes (g_h2c_mutex / g_c2h_mutex).
 *
 * Build: requires CGO_ENABLED=1 and libenq_aead.{so,h}. The cgo directives
 * below resolve the system install prefix (/usr/local); the top-level
 * Makefile additionally points cgo at the in-tree driver source so the test
 * binary builds without a prior `make install`.
 */

package device

/*
#cgo LDFLAGS: -L/usr/local/lib -lenq_aead
#cgo CFLAGS: -I/usr/local/include
#include "libenq_aead.h"
*/
import "C"
import (
	"errors"
	"os"
	"strings"
	"unsafe"
)

var (
	ErrInvalidMacTag   = errors.New("fpga_aead: authentication/tag verification mismatch")
	ErrFpgaIO          = errors.New("fpga_aead: hardware streaming I/O subsystem failure")
	FpgaOffloadEnabled = true
)

// init lets operators disable the hardware datapath at startup on hosts
// without the Alveo U200 / QDMA character devices (e.g. software-only test
// rigs), so the daemon uses the in-process ChaCha20-Poly1305 path instead of
// black-holing every packet. This is a startup mode switch, NOT a per-packet
// fallback: when offload is enabled a hardware fault always drops the packet
// (see RoutineEncryption / RoutineDecryption). Default is enabled.
//
//	ENQ_FPGA_OFFLOAD=0|off|false|no  -> software AEAD
func init() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ENQ_FPGA_OFFLOAD"))) {
	case "0", "off", "false", "no", "disable", "disabled":
		FpgaOffloadEnabled = false
	}
}
func FpgaAeadEncrypt(plaintext, aad, nonce, key []byte) ([]byte, []byte, error) {
	if len(nonce) != C.ENQ_AEAD_NONCE_SIZE || len(key) != C.ENQ_AEAD_KEY_SIZE {
		return nil, nil, ErrFpgaIO
	}
	ciphertext := make([]byte, len(plaintext))
	macTag := make([]byte, C.ENQ_AEAD_MAC_TAG_SIZE)
	var pPlaintext, pCiphertext *C.uint8_t
	if len(plaintext) > 0 {
		pPlaintext = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
		pCiphertext = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
	}
	var pAad *C.uint8_t
	if len(aad) > 0 {
		pAad = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}
	pNonce := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	pKey := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	pMacTag := (*C.uint8_t)(unsafe.Pointer(&macTag[0]))
	ret := C.fpga_aead_encrypt(pPlaintext, C.size_t(len(plaintext)), pAad, C.size_t(len(aad)), pNonce, pKey, pCiphertext, pMacTag)
	if ret != C.ENQ_AEAD_SUCCESS {
		return nil, nil, ErrFpgaIO
	}
	return ciphertext, macTag, nil
}
func FpgaAeadDecrypt(ciphertext, aad, nonce, macTag, key []byte) ([]byte, error) {
	if len(nonce) != C.ENQ_AEAD_NONCE_SIZE || len(key) != C.ENQ_AEAD_KEY_SIZE || len(macTag) != C.ENQ_AEAD_MAC_TAG_SIZE {
		return nil, ErrFpgaIO
	}
	plaintext := make([]byte, len(ciphertext))
	var pPlaintext, pCiphertext *C.uint8_t
	if len(ciphertext) > 0 {
		pPlaintext = (*C.uint8_t)(unsafe.Pointer(&plaintext[0]))
		pCiphertext = (*C.uint8_t)(unsafe.Pointer(&ciphertext[0]))
	}
	var pAad *C.uint8_t
	if len(aad) > 0 {
		pAad = (*C.uint8_t)(unsafe.Pointer(&aad[0]))
	}
	pNonce := (*C.uint8_t)(unsafe.Pointer(&nonce[0]))
	pMacTag := (*C.uint8_t)(unsafe.Pointer(&macTag[0]))
	pKey := (*C.uint8_t)(unsafe.Pointer(&key[0]))
	ret := C.fpga_aead_decrypt(pCiphertext, C.size_t(len(ciphertext)), pAad, C.size_t(len(aad)), pNonce, pMacTag, pKey, pPlaintext)
	switch ret {
	case C.ENQ_AEAD_SUCCESS:
		return plaintext, nil
	case C.ENQ_AEAD_ERR_TAG:
		return nil, ErrInvalidMacTag
	default:
		return nil, ErrFpgaIO
	}
}
