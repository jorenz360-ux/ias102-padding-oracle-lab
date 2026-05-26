# IAS 102 — Padding Oracle Lab

A deliberately-vulnerable AES-CBC server used to teach **padding oracle attacks** in the IAS 102 Information Assurance & Security course.

> ⚠️ **EDUCATIONAL USE ONLY.** This server is intentionally broken. Never deploy this code, or anything like it, to production. Run only on localhost.

---

## What This Lab Teaches

You will recover an encrypted secret message **without ever knowing the key** — by exploiting different error messages a vulnerable server returns. This is the classic **Vaudenay padding oracle attack** (2002), and it still works against badly-written code in production today.

**Key insight:** AES is mathematically unbreakable. The implementation around it isn't. This lab shows the difference.

---

## Prerequisites

- Python 3.8 or newer
- Two terminal windows (one for the server, one for the attacker)

---

## Setup

```bash
# Clone this repository
git clone https://github.com/YOUR_USERNAME/ias102-padding-oracle-lab.git
cd ias102-padding-oracle-lab

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Lab

### Step 1 — Start the vulnerable server

In **terminal 1**:

```bash
python server.py
```

You should see:

```
IAS 102 Padding Oracle Lab - VULNERABLE SERVER
[+] Random AES-128 key generated (hidden from attacker)
[+] Listening on http://127.0.0.1:5000
```

Leave this terminal running.

### Step 2 — Run the attack

In **terminal 2** (separate window):

```bash
python attack.py
```

Watch as the attacker recovers the plaintext byte-by-byte through padding error messages.

---

## What You Should Observe

The attack will print each recovered byte as it works through the ciphertext:

```
[*] Attacking block 1/3...
  [+] Position 15: 0x07 (random pad)
  [+] Position 14: 0x07 (random pad)
  ...
  [+] Position 0:  0x54 ('T')

[*] Attacking block 2/3...
  [+] Position 15: 0x21 ('!')
  ...

ATTACK COMPLETE
[+] Total server requests: ~6000
[+] RECOVERED PLAINTEXT:
    The IAS102 lab works! Password is pizza42
```

**You decrypted the message without the key.** The math was never broken — only the implementation was.

---

## Reflection Questions

1. The server uses real AES-128 with a random key. Why was the attack still possible?

2. Look at the `decrypt_endpoint` function in `server.py`. Identify the **specific line of code** that creates the vulnerability.

3. Modify the server to return **identical** error messages for all decryption failures. Run the attack again. Does it still work?

4. Why does TLS 1.3 remove CBC mode entirely? Look up "AEAD ciphers" and explain in 2-3 sentences what they fix.

5. Look up the **POODLE attack (2014)**. How is it related to this lab?

---

## Files in This Repository

| File               | Purpose                                             |
| ------------------ | --------------------------------------------------- |
| `server.py`        | The deliberately-vulnerable AES-CBC server          |
| `attack.py`        | The padding oracle attack script                    |
| `requirements.txt` | Python dependencies (Flask, cryptography, requests) |
| `README.md`        | This file                                           |

---

## How to Submit Your Deliverable

Per the lab slide, your deliverable is:

1. **Screenshot** of the attack output showing the recovered plaintext
2. **Request count** (the number printed at the end of the attack)
3. **Brief writeup** (1-2 paragraphs) explaining what changed when you modified the server's error messages, and why

Submit through the usual class platform.

---

## Safety Notice

This code:

- Only listens on `127.0.0.1` (localhost) — not exposed to your network
- Only attacks `127.0.0.1` — cannot be pointed at real websites
- Generates a fresh random key every time the server starts
- Contains no real secrets

**Do not modify it to attack systems you do not own.** Doing so is illegal in most jurisdictions and violates the IAS 102 code of conduct.

---

## License & Credits

Created for IAS 102 (Information Assurance & Security 2) — Summer Term.

Educational use only. Based on the padding oracle attack first published by Serge Vaudenay (EUROCRYPT 2002) and the Cryptopals Crypto Challenges Set 3, Challenge 17.

---

_The math holds. The implementations don't. Your job is to know the difference._
