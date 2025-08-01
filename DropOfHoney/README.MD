# Drop of Honey 

A BOF for triaging if a user account might be a honeypot in Active Directory using the ADSI (Active Directory Service Interfaces) API. Handy if you stumble upon suspicious credentials or roastable users.

<p align="center">
  <img src="https://cards.scryfall.io/large/front/5/8/588f1bc5-2230-4437-8d5e-a18f6e55b390.jpg?1562915819" 
       width="300" 
</p>


## Overview

Sometimes, you may suspect certain Active Directory user accounts are “honey” or honeypot users—created by blue teams or defenders to detect unauthorized use. For example:

- You found **suspicious credentials** in `description` attributes or GPO scripts.  
- You discovered a user with **kerberoastable** SPNs but suspiciously never logs in.  
- You want to **verify** whether a user is safe to use or might raise immediate flags.

User Example:
```
beacon> DropOfHoney o-kagachi
[+] sAMAccountName: O-Kagachi
[+] userAccountControl: 66048
    bits: NORMAL_ACCOUNT DONT_EXPIRE_PASSWORD 
    [Account is ENABLED]
[+] lastLogonTimestamp: 2/8/2025 7:04:20 AM
[+] pwdLastSet: 2/8/2025 7:04:14 AM
[+] whenCreated: 10/19/2024 3:30:44 AM
```
Computer Example:
```
beacon> DropOfHoney fs01
[+] sAMAccountName: FS01$
[+] userAccountControl: 4096
    bits: WORKSTATION_TRUST_ACCOUNT 
    [Account is ENABLED]
[+] lastLogonTimestamp: 10/20/2024 6:08:36 AM
[+] pwdLastSet: 10/20/2024 6:40:40 AM
[+] whenCreated: 10/19/2024 2:54:41 AM
```

By looking at these timestamps, account status, and any suspicious strings (like “Never logged in”), you can assess how risky it might be to use that account in your operations.
The BOF uses the ADSI (Active Directory Service Interfaces) API for LDAP queries.

## Interpreting the Results

* **lastLogonTimestamp** = `Never` or missing: indicates an account that has never been used. This is suspicious if you found credentials for it.
* **userAccountControl** = flags like `ACCOUNTDISABLE`, `SMARTCARD_REQUIRED`, `DONT_EXPIRE_PASSWORD`, etc. can tell you if the account is locked down or stands out as unusual.
* **description**: Sometimes credentials or notes are stored here. If it’s obviously “bait” or has a telling label, that’s suspicious.
* **whenCreated**: If it’s brand-new, that can also indicate a trap if you just discovered these credentials.

A user with an **old creation date** and **never** logs in, or has a strange combination of `userAccountControl` flags, might be a honeypot or seldom-used “canary” account. If you see suspicious indicators, you may want to **avoid** using that account.

There are some **public references on how honeypot accounts are typically configured**, which can help inform your detection strategy. Reviewing these can guide you on what attributes to look for:

* [StrandJS honeyuser.md](https://github.com/strandjs/ClassLabs/blob/main/Tools/IntroClass/honeyuser/honeyuser.md) – a practical example for students and defenders to set up a decoy account.
* [Arctic Wolf's guide on AD decoys](https://docs.arcticwolf.com/bundle/m_active_directory/page/configure_an_ad_decoy_account.html#create_an_ad_decoy_account) – official documentation on creating effective honeypot users in Active Directory.

These can provide insight into typical naming conventions, group memberships, and configuration patterns defenders may use.

