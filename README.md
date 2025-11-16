# NTLM
A Python implementation of [[MS-NLMP]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) (NT LAN Manager Authentification Protocol) message structures and related components.
This project aims to provide a clear and modular foundation for working with NTLM authentication messages such as **NEGOTIATE**, **CHALLENGE**, and **AUTHENTICATE**, following the Microsoft [MS-NLMP] specification.

## Project Structure
```
.
├── constants.py		# NTLM Constants and other constants
├── utils.py			# Global helpers (such as nonce, Z)
├── requirements.txt	# "List" of Python packages required (there is only one which is pycryptodome — seriously, who hasn't this lib???)
├── CRYPTO
│   ├── __init__.py
│   ├── compute.py		# Compute response and MIC
│   ├── hashing.py		# Hash functions (NTOWF/LMOWF)
│   ├── keys.py			# Key derivation
│   └── utils.py		# Cryptographic helpers
├── MESSAGES
│   ├── __init__.py
│   ├── authenticate.py	# NTLM AUTHENTICATE_MESSAGE structure
│   ├── base.py			# Base classes / shared logic
│   ├── challenge.py	# NTLM CHALLENGE_MESSAGE structure
│   └── negotiate.py	# NTLM NEGOTIATE_MESSAGE structure
└── STRUCTURES
    ├── __init__.py
    ├── av_pair.py			# AV_PAIR structure (TargetInfo Fields)
    ├── negotiate_flags.py	# NEGOTIATE_FLAGS bit structure
    ├── responses.py		# Response structures (LM/NT/NTLMv2 responses)
    ├── single_host.py		# SINGLE_HOST structure
    └── version.py			# VERSION structure

4 directories, 20 files
```

The codebase is divided into three main packages and two files:
- **constants.py** — Defines NTLM constants and protocol values.
- **utils.py** — Defines small shared helpers used across the project.
- **CRYPTO/** — Contains generic cryptographic helpers and low-level primitives used throughout NTLM.
- **MESSAGES/** — Contains the main NTLM message types.
- **STRUCTURES/** — Contains low-level NTLM data structures reused by messages.

---

## Overview

NTLM (NT LAN Manager) is an authentication protocol used in various Microsoft networking environments.  
This project focuses on *parsing, constructing, and serializing* NTLM messages in a readable way.

For now :
 - Negotiate Message, Challenge Message and Authenticate Message are finally working — I haven’t tested it in real communication yet.
 - Messages can be parsed/serialized using from_bytes and to_bytes methods.
 - All crypto functions are implemented, same for structures except NTLMSSP_MESSAGE_SIGNATURE.
 - Can fully use NTLMv1/NTLMv2.
 - MIC is supported!
 - Channel Bindings is not supported yet :'(

There is many things to improve, but I’ll focus on that once everything's working. (quite a liar.. sorry ^^')

### Examples 
#### literally my test.py

```python
from ntlm.constants import WINDOWS_MAJOR_VERSION_10, WINDOWS_MINOR_VERSION_0
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, AV_PAIR_LIST
from ntlm.MESSAGES import NEGOTIATE, CHALLENGE, AUTHENTICATE


flags = NEGOTIATE_FLAGS.NEGOTIATE_56\
        | NEGOTIATE_FLAGS.NEGOTIATE_KEY_EXCH\
        | NEGOTIATE_FLAGS.NEGOTIATE_128\
        | NEGOTIATE_FLAGS.NEGOTIATE_VERSION\
        | NEGOTIATE_FLAGS.NEGOTIATE_TARGET_INFO\
        | NEGOTIATE_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY\
        | NEGOTIATE_FLAGS.TARGET_TYPE_DOMAIN\
        | NEGOTIATE_FLAGS.NEGOTIATE_ALWAYS_SIGN\
        | NEGOTIATE_FLAGS.NEGOTIATE_NTLM\
        | NEGOTIATE_FLAGS.NEGOTIATE_SEAL\
        | NEGOTIATE_FLAGS.NEGOTIATE_SIGN\
        | NEGOTIATE_FLAGS.REQUEST_TARGET\
        | NEGOTIATE_FLAGS.NEGOTIATE_UNICODE

infos = {
    "domain": "Domain",
    "workstation": "Computer",
    "user": "User",
    "target": "Server",
    "password": "Password"
}

version = (WINDOWS_MAJOR_VERSION_10, WINDOWS_MINOR_VERSION_0, 17763)

negotiate_message = NEGOTIATE(flags, infos, version)
print(negotiate_message.to_bytes())

challenge_message = CHALLENGE(flags, infos, version)
print(challenge_message.to_bytes())

if challenge_message.TargetInfoFields.Len:
        target_info = AV_PAIR_LIST.from_bytes(challenge_message.Payload[challenge_message.TargetNameFields.Len:])
        infos["target_info"] = target_info

infos["negotiate_message"] = negotiate_message.to_bytes()
infos["server_challenge"] = challenge_message.ServerChallenge

authenticate_message = AUTHENTICATE(flags, infos, version)
print(authenticate_message.to_bytes())

print("\n#--- DEBUG ---#\n")
print("\n--- NEGOTIATE MESSAGE ---")
negotiate_message.display_info()

print("\n--- CHALLENGE MESSAGE ---")
challenge_message.display_info()

print("\n--- AUTHENTICATE MESSAGE ---")
authenticate_message.display_info()
```

Developed by Hatsu with so many 💖💖💖<br>
Hope you will enjoy it !

![](https://media1.tenor.com/m/CU-jv8_yz7AAAAAd/dancing-at-the-ghetto-cat-meme.gif)