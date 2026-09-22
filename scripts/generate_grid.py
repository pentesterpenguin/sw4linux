#!/usr/bin/env python3

"""
Generates obfuscated AES key components and position indices for C code output.
"""

import random

important_positions = [827, 730, 1022, 829, 912, 187, 726, 927, 836, 90, 336, 965, 523, 162, 279, 629]

FIRST_HALF = [
    0x8b, 0xcd, 0x10, 0x44, 0x94, 0xee, 0xc7, 0xf1,
    0x11, 0x38, 0x4c, 0x0f, 0x1f, 0x7e, 0x29, 0xb8,
]

SECOND_HALF = bytes([
    0x16, 0x7a, 0x20, 0x72, 0xa6, 0xc2, 0x34, 0x4c,
    0xc9, 0x71, 0x5c, 0x67, 0xbb, 0xb2, 0x2e, 0xd5
])

xor_key = bytes([
    0xD4, 0xD6, 0x11, 0x9F, 0x28, 0x57, 0xFC, 0x6A,
    0x3E, 0xB5, 0x24, 0x1C, 0x29, 0x10, 0xDD, 0x6B
])

# First half: generate XOR key for positions
xor_key_pos = [random.randint(0, 65535) for _ in range(16)]
xored_positions = [xor_key_pos[i] ^ important_positions[i] for i in range(16)]

# First half: XOR the key values
positions_in_bytes = bytes(FIRST_HALF)
xored_first_half = bytes(x ^ y for x, y in zip(xor_key, positions_in_bytes))

# Second half: use reversed xor_key
reversed_key = bytes(reversed(xor_key))
xored_second_half = bytes(SECOND_HALF[i] ^ reversed_key[i] for i in range(16))

# Verify correctness
assert all((xor_key_pos[i] ^ xored_positions[i]) == important_positions[i] for i in range(16))
assert bytes(xored_second_half[i] ^ reversed_key[i] for i in range(16)) == SECOND_HALF
assert bytes(xored_first_half[i] ^ xor_key[i] for i in range(16)) == positions_in_bytes
print("Verification OK\n")

print("uint16_t xor_key_pos[] = {")
print('    ' + ', '.join(f'0x{v:04X}' for v in xor_key_pos))
print("};")

print("\nuint16_t xored_key_index_first_chunk[] = {")
print('    ' + ', '.join(f'0x{v:04X}' for v in xored_positions))
print("};")

print("\nuint8_t xored_key_values_first_chunk[] = {")
print('    ' + ', '.join(f'0x{v:02X}' for v in xored_first_half))
print("};")

print("\nuint8_t xored_key_values_second_chunk[] = {")
print('    ' + ', '.join(f'0x{v:02X}' for v in xored_second_half))
print("};")