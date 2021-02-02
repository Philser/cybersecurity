# Scanning
```
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
```

## Web server

Hidden directory  
- /retro == **Wordpress** blog


## Wordpress enumeration

Found user wade
**Bruteforce?**
Found a comment on the blog, giving us the password: parzival  
Credentials: `wade:parzival`
(this is also in the rockyou.txt, so brute forcing would have also succeeded)

The session is very unstable.

- But there is a Wade user --> RDP?

Yep :) 

- winPEAS and PowerUp do not work ---> Manual enumeration?