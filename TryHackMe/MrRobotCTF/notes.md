# Scannings
```
Not shown: 65532 filtered ports
Reason: 65532 no-responses
PORT    STATE  SERVICE  REASON         VERSION
22/tcp  closed ssh      reset ttl 63
80/tcp  open   http     syn-ack ttl 63 Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open   ssl/http syn-ack ttl 63 Apache httpd
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
```

Web server at ports 80 & 443

![404 Page]()./img/wp_404.png

404 page shows us that this is a WP blog having a login page at
*http://10.10.252.56/wp-login.php*

Brute Force?


### First flag
/robots.txt reveals the first flag, which is accessible under /flag-1-of-3.txt

![Robots](./img/robots.png)


### Second flag

TODO: How?
`elliot:ER28-0652`

As elliot is administrator, we can generate a new password for the mich05654 user:
`mich05654:ayckn(GK9uXur3#Vm0yym)yr`

After gaining access to the machine by adding a reverse shell to the wordpress 404 page, we see that the next key is in directory /home/robot.
However, we do not have access to the file, but to a file containing a user and password (in md5):
`robot:c3fcd3d76192e4007dfb496cca67e13b`

Cracking the hash with HashCat

`> hashcat -a 0 -m 0 obtained_hash.txt /usr/share/wordlists/rockyou.txt`
`> abcdefghijklmnopqrstuvwxyz`

We then use python to obtain a terminal to login to the robot user
`echo "import pty; pty.spawn('/bin/bash')" > /tmp/asdf.py`
`python /tmp/asdf.py`