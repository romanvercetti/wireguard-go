#!/usr/bin/env bash
set -euo pipefail
echo "Starting patch automation..."
cat << 'EOF' > device/fpga_cipher.go
package device
/*
#cgo LDFLAGS: -L/usr/local/lib -lenq_aead
#cgo CFLAGS: -I/usr/local/include
#include "libenq_aead.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)
var (
	ErrInvalidMacTag   = errors.New("fpga_aead: authentication/tag verification mismatch")
	ErrFpgaIO          = errors.New("fpga_aead: hardware streaming I/O subsystem failure")
	FpgaOffloadEnabled = true
)
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
EOF

if ! grep -q "FpgaOffloadEnabled" device/send.go; then
    mv device/send.go device/send.go.bak
    awk '/func \(peer \*Peer\) CreateMessageData/ {
        print
        print "\tif FpgaOffloadEnabled {"
        print "\t\tnonceBytes := make([]byte, 12)"
        print "\t\tbinary.LittleEndian.PutUint64(nonceBytes[4:], nonce)"
        print "\t\tsymmetricKey := keypair.send.key[:]"
        print "\t\tvar associatedData []byte"
        print "\t\tciphertext, macTag, err := FpgaAeadEncrypt(plaintext, associatedData, nonceBytes, symmetricKey)"
        print "\t\tif err == nil {"
        print "\t\t\tmsg := \&MessageData{"
        print "\t\t\t\tType:     MessageDataType,"
        print "\t\t\t\tReceiver: keypair.remoteIndex,"
        print "\t\t\t\tNonce:    nonce,"
        print "\t\t\t}"
        print "\t\t\tmsg.Payload = append(ciphertext, macTag...)"
        print "\t\t\treturn msg, nil"
        print "\t\t}"
        print "\t}"
        next
    }1' device/send.go.bak > device/send.go
    rm device/send.go.bak
fi

if ! grep -q "FpgaOffloadEnabled" device/receive.go; then
    mv device/receive.go device/receive.go.bak
    awk '/func \(device \*Device\) PacketReceived/ {
        print
        print "\tif FpgaOffloadEnabled {"
        print "\t\tif len(payload) < 16 { return nil, errors.New(\"Packet below tag limits\") }"
        print "\t\tsplitIndex := len(payload) - 16"
        print "\t\tciphertext := payload[:splitIndex]"
        print "\t\tmacTag := payload[splitIndex:]"
        print "\t\tnonceBytes := make([]byte, 12)"
        print "\t\tbinary.LittleEndian.PutUint64(nonceBytes[4:], nonce)"
        print "\t\tsymmetricKey := keypair.receive.key[:]"
        print "\t\tvar associatedData []byte"
        print "\t\tplaintext, err := FpgaAeadDecrypt(ciphertext, associatedData, nonceBytes, macTag, symmetricKey)"
        print "\t\tif err == nil { return plaintext, nil }"
        print "\t\tif errors.Is(err, ErrInvalidMacTag) {"
        print "\t\t\tdevice.metrics.InboundAuthenticationFailures.Add(1)"
        print "\t\t\treturn nil, errors.New(\"Integrity verification failure\")"
        print "\t\t}"
        print "\t\treturn nil, err"
        print "\t}"
        next
    }1' device/receive.go.bak > device/receive.go
    rm device/receive.go.bak
fi
go fmt ./device/...
echo "Patch processing successful."
