# MagicBOFs
<p align="center">
<img src="https://github.com/user-attachments/assets/ab04384a-ec9b-4be6-883f-9cf5897e9b82" width="400" />


Welcome to MagicBOFs, a small set of Beacon Object Files (BOFs) that I developed over the time with a [Magic: The Gathering](https://en.wikipedia.org/wiki/Magic:_The_Gathering) theme. 

I've always thought it was interesting that [Sliver C2](https://github.com/BishopFox/sliver) was named after the [Slivers](https://mtg.fandom.com/wiki/Sliver) in MTG, even before I started playing the game. Now that I've gotten into *Magic: The Gathering*, I thought it would be fun to apply that theme to BOFs. 

Mapping BOFs to spells or sorceries from MTG just makes sense to me, and I’ll be adding more to this collection over time. Each one will likely take on some flavor of the MTG world — nothing too serious, just a funny naming scheme to me.

## What’s Here?

### **DropOfHoney**  
  A BOF for triaging if a user account might be a honeypot in Active Directory using the ADSI (Active Directory Service Interfaces) API. Handy if you stumble upon suspicious credentials or roastable users.

### **WarpWorld**  
A BOF that removes RDP session limits by dynamically patching `termsrv.dll` in memory—allowing multiple users to RDP into a machine at the same time.
**Shoutout to:**  
- **Benjamin Delpy (@gentilkiwi)** for `ts::multirdp` in **Mimikatz**  
- **@S3cur3Th1sSh1t** for porting the patch to [tspatch.c](https://gist.github.com/S3cur3Th1sSh1t/8294ec59d1ef38cba661697edcfacb9b)
