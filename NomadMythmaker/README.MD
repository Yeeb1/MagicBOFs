# NomadMythmaker

`NomadMythmaker` performs a **fast TCP port scan** and **HTTP banner grab** via  randomizing methods and User‑Agents to blend into normal traffic.
It is a lightweight  BOF adaptation of [django's](https://github.com/django-88)   [NomadScanner](https://github.com/django-88/NomadScanner).

<p align="center">
  <img src="https://cards.scryfall.io/large/front/9/a/9a5694fe-57d2-4359-857a-63213d986747.jpg?1562631113" width="300"/>
</p>

> *On the wild steppes, history vanishes in the dust. Only the mythmakers remain to say what was, and is, and will be.*

## Overview

* Scans **single IPs**, **CIDR notations**, or **ranges** (e.g. `10.13.13.23`, `10.13.37.0/24`, `172.16.17.1-172.16.17.3`).
* Scans **single ports**, **comma‑separated lists**, or **ranges** (e.g. `80`, `22,80,443`, `1-1024`).
* Sends an **HTTP/1.0 request** to open ports and captures the first **256 bytes** of the response banner.
* Randomizes **HTTP method** (`GET`, `HEAD`, `OPTIONS`) and **User-Agent** from a hardcoded list.
* Supports **domain fronting** by specifying an optional front-host.

> **Info**
> Ports are scanned sequentially (no multithreading).
> Each closed port incurs \~1s timeout, so NomadMythmaker is intended for small-scale scans.

### Syntax

```plaintext
beacon> inline-execute /opt/Arsenal/NomadMythmaker.x64.o 10.13.37.23 21,80-81,443,53,3389 foobar.com
```

### Output Example

#### Single IP
```plaintext
[+] 10.13.37.23:21 is open
    [*] HTTP banner: 220 FTP server ready.

[+] 10.13.37.231:80 is open
    [*] HTTP banner: HTTP/1.0 200 OK
Cache-Control: no-cache
Cache-Control: no-cache, no-store, must-revalidate
Connection: close
Content-Type: text/html; charset=utf-8
Date: Mon, 14 Jul 2025 16:29:14 GMT
Expires: -

[+] 10.13.37.23:443 is open
[+] 10.13.37.23:53 is open

=== Scan Summary ===
Total scanned: 7
Open: 5
Closed: 2
Time: 3.343 s
```

#### IP Range
```plaintext
[*] Parsing IP range: 192.168.178.65-192.168.178.70
[*] Generated 6 IPs from range

[*] Scanning 192.168.178.65
[+] 192.168.178.65:80 is open
    [*] HTTP Response: HTTP/1.1 301 Moved Permanently
Date: Mon, 14 Jul 2025 19:50:32 GMT
Location: https://front.example.com/
Connection: close
Content-Type: text/html
Content-Length: 56



<HTML><BODY><H1>301 Moved Permanently</H1></BODY></HTML>

[*] Scanning 192.168.178.66
[*] Scanning 192.168.178.67
[*] Scanning 192.168.178.68
[*] Scanning 192.168.178.69
[*] Scanning 192.168.178.70

=== Scan Summary ===
Total scanned: 6
Open: 1
Closed: 5
Time: 5.093 s
```
