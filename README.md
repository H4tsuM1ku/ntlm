# NTLM
A Python implementation of [[MS-NLMP]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) (NT LAN Manager Authentification Protocol) message structures and related components.
This project aims to provide a clear and modular foundation for working with NTLM authentication messages such as **NEGOTIATE**, **CHALLENGE**, and **AUTHENTICATE**, following the Microsoft [MS-NLMP] specification.

## Project Structure
```
.
├── README.md
├── MESSAGES
│   ├── __init__.py
│   ├── authenticate.py	# NTLM AUTHENTICATE_MESSAGE structure
│   ├── base.py			# Base classes / shared logic
│   ├── challenge.py	# NTLM CHALLENGE_MESSAGE structure
│   └── negotiate.py	# NTLM NEGOTIATE_MESSAGE structure
└── STRUCTURES
    ├── __init__.py
    ├── negotiate_flags.py	# NEGOTIATE_FLAGS bit structure
    └── version.py			# VERSION structure

3 directories, 9 files
```

The codebase is divided into two main packages:
- **MESSAGES/** — Contains the main NTLM message types.
- **STRUCTURES/** — Contains low-level NTLM data structures reused by messages.

---

## Overview

NTLM (NT LAN Manager) is an authentication protocol used in various Microsoft networking environments.  
This project focuses on *parsing, constructing, and serializing* NTLM messages in a readable, Pythonic way.

For now, only the Negotiate Message is working theorically... — I haven’t tested it in real communication yet.
There is many things to improve, but I’ll focus on that once everything's working.

### Example (literally my test.py)

```python
from ntlm.MESSAGES import NEGOTIATE
from ntlm.STRUCTURES import NEGOTIATEFLAGS, VERSION

# Build negotiate flags
flags = (0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0)
negotiate_flags = NEGOTIATEFLAGS(*flags)
flags_bytes = negotiate_flags.to_bytes()
print(flags_bytes)

# Build version info
version = VERSION(major=10, minor=0, build=19045)
version_bytes = version.to_bytes()
print(version_bytes)

domain_name = "MIKU.WORLD"
workstation_name = "Hatsu"
major = 0xDE
minor = 0xAD
build = 0xBEEF

n = NEGOTIATE(flags, domain_name, workstation_name, major, minor, build)
print(n.to_bytes())
```

Developed by Hatsu with so many <3 <3 <3
Hope you will enjoy it !

![](https://tenor.com/view/dancing-at-the-ghetto-cat-meme-dog-meme-alien-gif-670934913724370864)