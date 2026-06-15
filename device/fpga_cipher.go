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
	if ret != C.ENQ_AEAD_SUCCESS { return nil, nil, ErrFpgaIO }
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
	case C.ENQ_AEAD_SUCCESS: return plaintext, nil
	case C.ENQ_AEAD_ERR_TAG: return nil, ErrInvalidMacTag
	default: return nil, ErrFpgaIO
	}
}
