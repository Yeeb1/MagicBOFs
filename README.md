# MagicBOFs
<p align="center">
<img src="https://github.com/user-attachments/assets/bd471485-d076-4411-8aab-5f8fb1247d91" width="400" />



Welcome to MagicBOFs, a small set of Beacon Object Files (BOFs) that I developed over the time with a [Magic: The Gathering](https://en.wikipedia.org/wiki/Magic:_The_Gathering) theme. 

I've always thought it was interesting that [Sliver C2](https://github.com/BishopFox/sliver) was named after the [Slivers](https://mtg.fandom.com/wiki/Sliver) in MTG, even before I started playing the game. Now that I've gotten into *Magic: The Gathering*, I thought it would be fun to apply that theme to BOFs. 

Mapping BOFs to spells or sorceries from MTG just makes sense to me, and I’ll be adding more to this collection over time. Each one will likely take on some flavor of the MTG world — nothing too serious, just a funny naming scheme to me.

## What’s Here?

### **DropOfHoney**  
A BOF for triaging if a user account might be a honeypot in Active Directory using the ADSI (Active Directory Service Interfaces) API. Handy if you stumble upon suspicious credentials or roastable users.

### **InnocentTraveler** 
A BOF that creates a new local administrator account with an optional or randomly generated password. Useful for establishing persistence or backup access during post-exploitation. Automatically resolves the localized name of the Administrators group.

### **NomadMythmaker**

A BOF that performs small-scale TCP port scans by fronting through a customizable domain and grabbing HTTP banners. Ports are scanned **sequentially** (no multithreading), with each closed port incurring a \~1 s timeout—ideal for quick, targeted reconnaissance.
**Shoutout to:**
* **django-88** for **NomadScanner** ([GitHub](https://github.com/django-88/NomadScanner))


### **TappingAtTheWindow**  
A BOF that acts as a lightweight implementation of `curl`, allowing you to peek at remote services without opening a SOCKS proxy. It can be used to inspect HTTP response headers and TLS certificates, making it useful for detecting if certificates have been swapped out or intercepted.

### **WarpWorld**  
A BOF that removes RDP session limits by dynamically patching `termsrv.dll` in memory—allowing multiple users to RDP into a machine at the same time.
**Shoutout to:**  
- **Benjamin Delpy (@gentilkiwi)** for `ts::multirdp` in **Mimikatz**  
- **@S3cur3Th1sSh1t** for porting the patch to [tspatch.c](https://gist.github.com/S3cur3Th1sSh1t/8294ec59d1ef38cba661697edcfacb9b)

