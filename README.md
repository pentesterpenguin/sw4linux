# SW4Linux – Passive Linux Implant

A proof-of-concept implant demonstrating covert activation via ICMP magic packets, 
authenticated with AES-256-GCM encryption, and secured with X25519 ECDH key exchange.

Inspired by [SLEEPWALKER](https://github.com/HackingLZ/sleepwalker/) 
([Technical writeup](https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/)).

## Features

- **Zero network footprint at rest** – Passive listener, no outbound connections until triggered
- **ICMP-based covert activation** – Triggered by specially crafted ICMP echo requests (appears as normal ping traffic)
- **AES-256-GCM encryption** – Authenticated encryption for trigger payload and reverse shell communication
- **X25519 ECDH key exchange** – Ephemeral per-session key agreement for forward secrecy
- **Multi-layer obfuscation** – Per-byte XOR string encryption + grid-based key scattering
- **Anti-analysis detection** – VM/hypervisor detection, debugger detection, container detection

## Architecture

### Trigger Mechanism
The implant waits for an ICMP echo request (ping) with:
- **Magic header:** `SW4L` (4 bytes)
- **Nonce:** 12 bytes (IV for GCM)
- **Ciphertext:** 13 bytes (encrypted plaintext)
- **Auth tag:** 16 bytes (GCM authentication tag)
- **Padding:** 11 bytes (to reach 56-byte payload, indistinguishable from normal ping [size wise])

The encrypted plaintext contains:
- trigger string 'Open Sesame' + port number where operator is listening

### Activation Sequence
1. Implant receives valid ICMP trigger packet with correct AES-GCM authentication
2. Decrypts payload to extract callback IP (source of trigger) and port
3. Forks a child process
4. Child performs X25519 ECDH handshake with operator
5. Both sides derive shared session key via HKDF-SHA256
6. Reverse shell spawned with all communication encrypted via AES-256-GCM

### Evasion

**Startup checks** (silently exits if detected):
- VM/hypervisor detection: DMI strings (sys_vendor and product_name)
- Debugger detection: via `/proc/self/status`, check for `TracerPid`
- Container detection: `/.dockerenv`, check if rootfs is `overlayfs`, PID 1 process name

**Anti-analysis:**
- All suspicious strings encrypted with per-byte XOR keys
- Key material scattered in binary via grid.bin + obfuscated index access
- Raw syscalls for `dup3` and `execve` to bypass LD_PRELOAD hooks

## Building

**Requirements:**
- GCC / Clang
- OpenSSL 3.0+ development headers (`libssl-dev`)
- `objcopy` (GNU binutils)

```bash
make clean && make
```

Produces: `implant` (stripped, ~28KB)

## Usage

`controller/operator.py` is quite easy to use. It automates the listening part, sending the magic packet, handling multiple sessions...

## Limitations

- No persistence mechanism (survives only for current boot)
- Limited command set (reverse shell only, no command dispatcher)
- Requires root access (raw ICMP socket)
- X86-64 Linux only (architecture-specific syscalls)
- **Static symmetric key hardcoded in source** The AES key is visible in `crypto.c` (not a secret). Real implants use asymmetric authentication (this is a PoC not an operational tool)

## Disclaimer

For educational and research purposes only. Use only on systems you own or have explicit written permission to test.

## References

- [SLEEPWALKER (Windows)](https://github.com/HackingLZ/sleepwalker/)
- [SLEEPWALKER Technical Writeup](https://r136a1.dev/2026/08/24/sleepwalker-a-passive-backdoor-with-its-own-command-language/)