# NTLM
A Python implementation of [[MS-NLMP]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4) (NT LAN Manager Authentification Protocol) message structures and related components.
This project aims to provide a clear and modular foundation for working with NTLM authentication messages such as **NEGOTIATE**, **CHALLENGE**, and **AUTHENTICATE**, following the Microsoft [MS-NLMP] specification.

## Project Structure
```
.
├── __init__.py
├── constants.py # NTLM Constants
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

The codebase is divided into two main packages and a file:
- **constants.py** – Defines NTLM constants and protocol values.
- **MESSAGES/** — Contains the main NTLM message types.
- **STRUCTURES/** — Contains low-level NTLM data structures reused by messages.

---

## Overview

NTLM (NT LAN Manager) is an authentication protocol used in various Microsoft networking environments.  
This project focuses on *parsing, constructing, and serializing* NTLM messages in a readable, Pythonic way.

For now, only the Negotiate Message is working theorically... — I haven’t tested it in real communication yet.
The NEGOTIATE_FLAGS class was improved to be easier to use. (I really love it!).

/!\ Ok maybe NEGOTIATE_FLAGS has some bugs for now and you can't use more than one flag... /!\\.

There is many things to improve, but I’ll focus on that once everything's working. (quiet a liar.. sorry ^^')

### Example (literally my test.py)

```python
from ntlm.MESSAGES import NEGOTIATE
from ntlm.STRUCTURES import NEGOTIATE_FLAGS, VERSION

# Build version info
version = VERSION(major=10, minor=0, build=19045)
version_bytes = version.to_bytes()
print(version_bytes)

# Build negotiate flags
flags = NEGOTIATE_FLAGS.NEGOTIATE_OEM |\
        NEGOTIATE_FLAGS.NEGOTIATE_VERSION
        #| NEGOTIATE_FLAGS.NEGOTIATE_OEM_DOMAIN_SUPPLIED
        #| NEGOTIATE_FLAGS.NEGOTIATE_OEM

print(flags, dir(flags))

domain_name = "MIKU.WORLD"
workstation_name = "Hatsu"
major = 0xD3
minor = 0x55
build = 0x4444

n = NEGOTIATE(flags, domain_name, workstation_name, major, minor, build)
print(n.pack())
```

Developed by Hatsu with so many 💖💖💖<br>
Hope you will enjoy it !

![](https://media1.tenor.com/m/CU-jv8_yz7AAAAAd/dancing-at-the-ghetto-cat-meme.gif)