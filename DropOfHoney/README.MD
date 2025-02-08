# DropOfHoney 

## Overview

Sometimes, you may suspect certain Active Directory user accounts are “honey” or honeypot users—created by blue teams or defenders to detect unauthorized use. For example:

- You found **suspicious credentials** in `description` attributes or GPO scripts.  
- You discovered a user with **kerberoastable** SPNs but suspiciously never logs in.  
- You want to **verify** whether a user is safe to use or might raise immediate flags.

**DropOfHoney** is a Beacon Object File (BOF) that retrieves several key attributes from AD about a objects’s **sAMAccountName**, including:

- **description**  
- **sAMAccountName**  
- **lastLogonTimestamp**  
- **pwdLastSet**  
- **whenCreated**  
- **userAccountControl** (with a bitmask “decoding” of flags)

By looking at these timestamps, account status, and any suspicious strings (like “Never logged in”), you can assess how risky it might be to use that account in your operations.


## Interpreting the Results

- **lastLogonTimestamp** = `Never` or missing: indicates an account that has never been used. This is suspicious if you found credentials for it.  
- **userAccountControl** = flags like `ACCOUNTDISABLE`, `SMARTCARD_REQUIRED`, `DONT_EXPIRE_PASSWORD`, etc. can tell you if the account is locked down or stands out as unusual.  
- **description**: Sometimes credentials or notes are stored here. If it’s obviously “bait” or has a telling label, that’s suspicious.  
- **whenCreated**: If it’s brand-new, that can also indicate a trap if you just discovered these credentials.  

A user with an **old creation date** and **never** logs in, or has a strange combination of `userAccountControl` flags, might be a honeypot or seldom-used “canary” account. If you see suspicious indicators, you may want to **avoid** using that account.
