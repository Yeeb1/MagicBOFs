
# TappingAtTheWindow

TappingAtTheWindow is a basic implementation of `curl` designed to peek at remote services without opening a SOCKS proxy. It enables operators to fetch TLS certificates, response headers, and HTML titles from remote web services, making it useful for reconnaissance, fingerprinting, and monitoring certificate changes for potential interception.

<p align="center">
  <img src="https://cards.scryfall.io/large/front/f/a/fa428edc-4d7d-455a-9c9d-9dc71b502e64.jpg?1673160583" 
       width="300" 
</p>

## Overview  

`TappingAtTheWindow` provides two main functionalities:  

- **finger** → Retrieve **TLS certificates**, response headers, and the HTML `<title>` from a URL.  
- **print** → Fetch and print the raw page content (basically CURL).

### **Basic Usage**
```plaintext
beacon> TappingAtTheWindow <finger|print> <url> [--ua "Custom User-Agent"]
```

Finger Output:
```plaintext
beacon> TappingAtTheWindow finger https://example.com

[+] Response Headers:
HTTP/1.1 200 OK
Cache-Control: max-age=3120
Connection: keep-alive
Date: Sun, 16 Feb 2025 19:23:45 GMT
Content-Length: 1342
Content-Type: text/html
Last-Modified: Tue, 21 Jan 2025 15:37:10 GMT
ETag: "9f4b6de1c97a4e8db3f58eaf4127bc05:1737488230.154672"
Alt-Svc: h3=":443"; ma=86400,h3-29=":443"; ma=86400,h3-Q050=":443"; ma=86400,quic=":443"; ma=86400; v="46,43"

[+] TLS Certificate Subject: *.example.com
[+] TLS Certificate Issuer	: DigiCert Global G3 TLS ECC SHA384 2020 CA1
[+] Valid From		: 20/01/2025
[+] Valid Until		: 20/01/2026
[+] Page Title		: Example Domain
```
