# NTLM
A Python implementation of [[MS-NLMP]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) (NT LAN Manager Authentification Protocol) message structures and related components.
This project aims to provide a clear and modular foundation for working with NTLM authentication messages such as **NEGOTIATE**, **CHALLENGE**, and **AUTHENTICATE**, following the Microsoft [MS-NLMP] specification.

## Project Structure
```
.
├── __init__.py
├── constants.py # NTLM Constants
├── CRYPTO
│   ├── __init__.py
│   └── utils.py		# Non-specific cryptographic functions (such as nonce)
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
    ├── single_host.py		# SINGLE_HOST structure
    └── version.py			# VERSION structure

4 directories, 14 files
```

The codebase is divided into two main packages and a file:
- **constants.py** – Defines NTLM constants and protocol values.
- **CRYPTO/** — Contains generic cryptographic helpers and low-level primitives used throughout NTLM.
- **MESSAGES/** — Contains the main NTLM message types.
- **STRUCTURES/** — Contains low-level NTLM data structures reused by messages.

---

## Overview

NTLM (NT LAN Manager) is an authentication protocol used in various Microsoft networking environments.  
This project focuses on *parsing, constructing, and serializing* NTLM messages in a readable, Pythonic way.

For now :
 - Negotiate Message is working theorically... — I haven’t tested it in real communication yet.
 - Same for Challenge Message!
 - Working on Authenticate Message, session_key is missing and composition of the MIC.
 - Many stuctures are missing (TIMESTAMP, LM_RESPONSE, NT_RESPONSE, ...)

There is many things to improve, but I’ll focus on that once everything's working. (quite a liar.. sorry ^^')

### Example (literally my test.py)

```python
from ntlm.constants import MsvAvSingleHost, MsvAvNbComputerName, MsvAvNbDomainName
from ntlm.STRUCTURES import NEGOTIATE_FLAGS
from ntlm.MESSAGES import NEGOTIATE, CHALLENGE


flags = NEGOTIATE_FLAGS.NEGOTIATE_OEM\
        | NEGOTIATE_FLAGS.NEGOTIATE_VERSION\
        | NEGOTIATE_FLAGS.NEGOTIATE_OEM_DOMAIN_SUPPLIED\
        | NEGOTIATE_FLAGS.NEGOTIATE_OEM_WORKSTATION_SUPPLIED

print(hex(flags), flags.dict)

domain_name = "MIKU.WORLD"
workstation_name = "Hatsu"
major = 0xD3
minor = 0x55
build = 0x4444

negotiate_message = NEGOTIATE(flags, domain_name, workstation_name)
print(negotiate_message.pack())


flags = flags.clear()
flags |= NEGOTIATE_FLAGS.NEGOTIATE_OEM\
        | NEGOTIATE_FLAGS.REQUEST_TARGET\
        | NEGOTIATE_FLAGS.NEGOTIATE_TARGET_INFO

av_list = {
        MsvAvNbComputerName:"Hatsu.MIKU.WORLD",
        MsvAvNbDomainName:"MIKU.WORLD",
        MsvAvSingleHost:""
}

print(hex(flags), flags.dict)

target_name = "Hatsu"

challenge_message = CHALLENGE(flags, workstation_name, av_list)
print(challenge_message.pack())
```

Developed by Hatsu with so many 💖💖💖<br>
Hope you will enjoy it !

![](https://media1.tenor.com/m/CU-jv8_yz7AAAAAd/dancing-at-the-ghetto-cat-meme.gif)