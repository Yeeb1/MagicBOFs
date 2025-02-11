
# Warp World 

<p align="center">
  <img src="https://cards.scryfall.io/large/front/1/e/1e1a5e62-9170-4117-ae38-761293b11de4.jpg?1599765093" 
       width="300" 
</p>

## Overview

**WarpWorld** is a **Beacon Object File (BOF)** that patches `termsrv.dll` in memory to enable **multiple concurrent RDP (Remote Desktop Protocol) sessions** on Windows machines. On clients, Windows normally **restricts RDP sessions** to a single user at a time, this BOF removes that limitation.



### Shoutouts
- **Benjamin Delpy (@gentilkiwi)** for the original **ts::multirdp** feature in **Mimikatz**.  
- **[@S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t)** for his C implementation of [tspatch.c](https://gist.github.com/S3cur3Th1sSh1t/8294ec59d1ef38cba661697edcfacb9b).  

##  Usage

This BOF requires no arguments—simply execute it to patch `termsrv.dll` dynamically.

```plaintext
beacon> WarpWorld
```

###  Expected Output

If successful, you should see:
```
beacon> WarpWorld
[+] SeDebugPrivilege enabled!
[+] 'termsrv.dll' service patched at address=00007FF9F3381000
[+] Patch completed successfully! You can now Multi-RDP on the host.
```
If the system has already been patched, you'll see:
```
[-] No matching pattern found in memory.
[-] Patch failed!
```
