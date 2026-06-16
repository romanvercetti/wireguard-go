# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go.

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## ENQUANTUM FPGA AEAD Hardware Offload

This build of wireguard-go is integrated with the ENQ-OS FPGA AEAD hardware
offload datapath. The symmetric transport AEAD (normally ChaCha20-Poly1305 in
software) is rerouted to the ENQUANTUM AEAD IP core on an AMD Xilinx Alveo U200
(OpenNIC shell) over PCIe Gen3 x16, accessed through the Xilinx QDMA character
devices `/dev/qdma_h2c_0` (host-to-card) and `/dev/qdma_c2h_0` (card-to-host).

### Architecture

* **`device/fpga_cipher.go`** — cgo bridge wrapping `fpga_aead_encrypt()` and
  `fpga_aead_decrypt()` from the `libenq_aead` driver (`../libenq_aead.{c,h}`).
* **TX (`device/send.go`, `RoutineEncryption`)** — the padded transport
  plaintext, empty AAD, 12-byte nonce and 32-byte session send key are streamed
  to `FpgaAeadEncrypt`; the resulting ciphertext and 16-byte tag are reassembled
  in place as `header ‖ ciphertext ‖ tag`, byte-identical to the software
  `cipher.AEAD.Seal` layout.
* **RX (`device/receive.go`, `RoutineDecryption`)** — each transport record is
  split into `ciphertext ‖ tag`; both, plus empty AAD, the nonce and the session
  receive key, are handed to `FpgaAeadDecrypt` for authenticated decryption.
* **Keys (`device/keypair.go`, `device/noise-protocol.go`)** — `cipher.AEAD`
  does not expose its key, so `BeginSymmetricSession` retains the raw 256-bit
  send/receive transport keys (`sendKey` / `receiveKey`) for the hardware path.

### Concurrency

No locking is added in the VPN code around the hardware calls. The encryption
and decryption worker goroutines invoke the driver directly; `libenq_aead`
serialises the QDMA pipeline internally via its own POSIX mutexes
(`g_h2c_mutex`, `g_c2h_mutex`).

### Error handling

* `ENQ_AEAD_ERR_IO` (-1): a hardware/DMA state fault is logged as a severe
  error and the packet is dropped. There is **no** per-packet fallback to
  software AEAD — a hardware state failure must trigger an active investigation.
* `ENQ_AEAD_ERR_TAG` (-2): authentication failed; the packet is dropped
  silently, matching standard WireGuard behaviour.

### Runtime switch

Hosts without the Alveo U200 / QDMA character devices (e.g. software-only test
rigs) can disable the hardware datapath at **startup** so the daemon uses the
in-process ChaCha20-Poly1305 path instead of black-holing every packet:

```
$ ENQ_FPGA_OFFLOAD=0 wireguard-go wg0
```

This is a startup mode switch, not a per-packet fallback. When offload is
enabled, a hardware fault always drops the packet (see above). The switch is
enabled by default.

### Building with the offload

The cgo bridge requires `CGO_ENABLED=1` and the `libenq_aead` shared object and
header. The top-level `Makefile` builds the driver from `../libenq_aead.c`
(override with `ENQ_AEAD_DIR`), points cgo at it, and bakes in an rpath, so a
system-wide `make install` of the `.so` is not required to build or run the
binary:

```
$ make            # builds ../libenq_aead.so then the cgo wireguard-go binary
$ make install    # also installs the .so/.h under $(PREFIX)/{lib,include}
```

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
