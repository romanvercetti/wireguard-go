#!/usr/bin/env bash
#
# patch_vpn.sh — ENQ FPGA AEAD offload integration verifier.
#
# The FPGA hardware-offload hooks are now committed directly into the
# wireguard-go datapath (device/send.go, device/receive.go, device/keypair.go,
# device/noise-protocol.go) and the cgo bridge (device/fpga_cipher.go).
#
# This script no longer rewrites any source (the previous awk-based patcher
# targeted an older wireguard-go architecture — CreateMessageData /
# PacketReceived / keypair.send.key — that does not exist in this batched
# datapath, and would have produced a non-compiling tree). It now simply:
#   1. builds the libenq_aead.so the cgo bridge links against, and
#   2. asserts the in-tree integration hooks are present.
#
set -euo pipefail

cd "$(dirname "$0")"
AEAD_DIR="$(realpath ..)"

ok()   { printf '  [ OK ] %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1" >&2; exit 1; }

echo "ENQ FPGA AEAD offload — integration check"

# 1. Build the offload shared object (cgo links against ../libenq_aead.so).
echo "Building libenq_aead.so ..."
make -C "$AEAD_DIR" >/dev/null
[ -f "$AEAD_DIR/libenq_aead.so" ] || fail "libenq_aead.so was not produced"
ok "libenq_aead.so built"

# 2. Assert the integration hooks exist in the real datapath.
grep -q 'import "C"'                      device/fpga_cipher.go   || fail "fpga_cipher.go: cgo bridge missing"
grep -q 'func FpgaAeadEncrypt'            device/fpga_cipher.go   || fail "fpga_cipher.go: FpgaAeadEncrypt missing"
grep -q 'func FpgaAeadDecrypt'            device/fpga_cipher.go   || fail "fpga_cipher.go: FpgaAeadDecrypt missing"
ok "fpga_cipher.go cgo bridge present"

grep -q 'sendKey'    device/keypair.go    || fail "keypair.go: raw sendKey field missing"
grep -q 'receiveKey' device/keypair.go    || fail "keypair.go: raw receiveKey field missing"
grep -q 'copy(keypair.sendKey'    device/noise-protocol.go || fail "noise-protocol.go: sendKey not captured"
grep -q 'copy(keypair.receiveKey' device/noise-protocol.go || fail "noise-protocol.go: receiveKey not captured"
ok "raw transport keys wired into keypair derivation"

grep -q 'FpgaAeadEncrypt' device/send.go    || fail "send.go: TX encryption hook missing"
grep -q 'FpgaAeadDecrypt' device/receive.go || fail "receive.go: RX decryption hook missing"
ok "TX/RX datapath hooks present"

echo "Integration check passed."
echo "Build the daemon with: make    (CGO links ../libenq_aead.so via rpath)"
echo "Disable offload on non-FPGA hosts with: ENQ_FPGA_OFFLOAD=0 ./wireguard-go wg0"
