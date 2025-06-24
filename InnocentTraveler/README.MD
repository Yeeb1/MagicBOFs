
# InnocentTraveler

`InnocentTraveler` creates a **local administrator** account on the host system. It can be used to persist access or establish additional footholds in post-exploitation scenarios.

If no password is supplied, a random password is generated automatically. This BOF uses native Windows APIs like `NetUserAdd` and `NetLocalGroupAddMembers` to perform account creation and privilege assignment.

<p align="center">
  <img src="https://cards.scryfall.io/large/front/7/a/7a043975-59b4-490c-bf33-c08bd7b40bd3.jpg?1645227274" 
       width="300" 
</p>

## Overview

* Adds a **new local user**.
* Assigns the user to the **Administrators** group (localized-safe).
* Allows optional password specification.
* Generates random password if none provided.
* Uses **Win32 API only**.
* Works with both **inline-execute** and **CNA-invoked** workflows (packed arguments).

Syntax:
```plaintext
beacon> AddUser <username> [password]
```

Output Example:
```plaintext
[*] Creating user: defaultuser
[*] Password: UhM*E9w1oTgL&D8v0nSfK^C7uZmReJ%
[+] User defaultuser created.
[+] Added defaultuser to local admin group (Administratoren).
```

<p align="center">
  <img src="https://cards.scryfall.io/large/back/7/a/7a043975-59b4-490c-bf33-c08bd7b40bd3.jpg?1645227274" 
       width="300" 
</p>
