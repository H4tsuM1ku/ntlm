# NTLM
A Python implementation of [[MS-NLMP]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) (NT LAN Manager Authentification Protocol) message structures and related components.
This project aims to provide a clear and modular foundation for working with NTLM authentication messages such as **NEGOTIATE**, **CHALLENGE**, and **AUTHENTICATE**, following the Microsoft [MS-NLMP] specification.

## Project Structure
```
.
├── __init__.py
├── constants.py		# NTLM Constants
├── requirements.txt	# "List" of Python packages required (there is only one which is pycryptodome — seriously, who hasn't this lib???)
├── CRYPTO
│   ├── __init__.py
│   ├── compute.py		# High-level crypto operations
│   ├── hashing.py		# Hash functions (NTOWF/LMOWF)
│   ├── keys.py			# Key derivation
│   └── utils.py		# (Non-specific) Cryptographic helpers (such as nonce)
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

4 directories, 19 files
```

The codebase is divided into three main packages and a file:
- **constants.py** – Defines NTLM constants and protocol values.
- **CRYPTO/** — Contains generic cryptographic helpers and low-level primitives used throughout NTLM.
- **MESSAGES/** — Contains the main NTLM message types.
- **STRUCTURES/** — Contains low-level NTLM data structures reused by messages.

---

## Overview

NTLM (NT LAN Manager) is an authentication protocol used in various Microsoft networking environments.  
This project focuses on *parsing, constructing, and serializing* NTLM messages in a readable way.

For now :
 - Negotiate Message is working theorically... — I haven’t tested it in real communication yet.
 - Same for Challenge Message!
 - Working on Authenticate Message, soon the end.
 - Almost all structures are implemented, same for crypto functions (missing RC4).
 - Some bugs for fully use NTLMv2.
 - MIC and Channel Bindings are not supported yet :'(

There is many things to improve, but I’ll focus on that once everything's working. (quite a liar.. sorry ^^')

### Examples 
#### literally my test.py

```python
from ntlm.constants import WINDOWS_MAJOR_VERSION_6, WINDOWS_MINOR_VERSION_0
from ntlm.CRYPTO import LMOWFv1, NTOWFv1
from ntlm.STRUCTURES import NEGOTIATE_FLAGS
from ntlm.MESSAGES import NEGOTIATE, CHALLENGE


flags = NEGOTIATE_FLAGS.NEGOTIATE_UNICODE\
        | NEGOTIATE_FLAGS.NEGOTIATE_VERSION\
        | NEGOTIATE_FLAGS.NEGOTIATE_OEM_DOMAIN_SUPPLIED\
        | NEGOTIATE_FLAGS.NEGOTIATE_OEM_WORKSTATION_SUPPLIED

infos = {
    "domain": "MIKU.WORLD",
    "workstation": "Hatsu",
    "NT_hash": NTOWFv1("World"),
    "LM_hash": LMOWFv1("is"),
    "user": "Mine",
    "target": "Server"
}

version = (WINDOWS_MAJOR_VERSION_6, WINDOWS_MINOR_VERSION_0, 0x4444)

negotiate_message = NEGOTIATE(flags, infos, version)
print(negotiate_message.pack())

flags = flags.clear()
flags |= NEGOTIATE_FLAGS.NEGOTIATE_KEY_EXCH\
        | NEGOTIATE_FLAGS.NEGOTIATE_56\
        | NEGOTIATE_FLAGS.NEGOTIATE_128\
        | NEGOTIATE_FLAGS.NEGOTIATE_VERSION\
        | NEGOTIATE_FLAGS.TARGET_TYPE_SERVER\
        | NEGOTIATE_FLAGS.NEGOTIATE_ALWAYS_SIGN\
        | NEGOTIATE_FLAGS.NEGOTIATE_NTLM\
        | NEGOTIATE_FLAGS.NEGOTIATE_SEAL\
        | NEGOTIATE_FLAGS.NEGOTIATE_SIGN\
        | NEGOTIATE_FLAGS.NEGOTIATE_OEM\
        | NEGOTIATE_FLAGS.NEGOTIATE_UNICODE

challenge_message = CHALLENGE(flags, infos, {}, version)
print(challenge_message.pack())
```

#### test.py crypto part

The constants are from the documentation and have been checked with documentation examples, you can compare them.

```python
from ntlm.CRYPTO import *
from ntlm.STRUCTURES import NEGOTIATE_FLAGS

ServerChallenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
ClientChallenge = b"\xaa"*8
RandomSessionKey = b"\x55"*16

ResponseKeyLM = LMOWFv1("Password")
ResponseKeyNT = NTOWFv1("Password")

# NTLM v1 no extended security

flags = NEGOTIATE_FLAGS.NEGOTIATE_NTLM | NEGOTIATE_FLAGS.NEGOTIATE_LM_KEY

LmChallengeResponse, NtChallengeResponse, SessionBaseKey = compute_response(flags, ResponseKeyNT, ResponseKeyLM, ServerChallenge, ClientChallenge)
KeyExchangeKey = KXKEY(flags, SessionBaseKey, ResponseKeyLM, ServerChallenge, LmChallengeResponse)

print(LmChallengeResponse, NtChallengeResponse, SessionBaseKey, KeyExchangeKey)

# NTLM v1 extended security

flags = NEGOTIATE_FLAGS.NEGOTIATE_NTLM | NEGOTIATE_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY

LmChallengeResponse, NtChallengeResponse, SessionBaseKey = compute_response(flags, ResponseKeyNT, ResponseKeyLM, ServerChallenge, ClientChallenge)
KeyExchangeKey = KXKEY(flags, SessionBaseKey, ResponseKeyNT, ServerChallenge, LmChallengeResponse)

print(LmChallengeResponse, NtChallengeResponse, SessionBaseKey, KeyExchangeKey)
```

Developed by Hatsu with so many 💖💖💖<br>
Hope you will enjoy it !

![](https://media1.tenor.com/m/CU-jv8_yz7AAAAAd/dancing-at-the-ghetto-cat-meme.gif)