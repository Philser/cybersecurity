## Scanning
```
PORT      STATE SERVICE REASON         VERSION
9999/tcp  open  abyss?  syn-ack ttl 63
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    syn-ack ttl 63 SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
```
**Port 10000**
- Web server
- Has a nice info graphic about common vulnerabilities and their distribution across the ecosystem (Hint?)
- We find a */bin* directory that gives us access to the program running under port 9999

![3313118a4cacd5eec8b0fa2bc14ed5ff.png](:/b76ed8ce343c4f79b9d0a2be624c6f29)

## Exploitation

- We seem to have an exploitable binary:

![100cc5d0fc42933438b48e3c2aefb543.png](:/67dfd6bd8a6e4377bff270116350e655)

- Overflow with 700 bytes  
- **Offset: 524**
- Problem:
	- Stack adresses contain \x00 byte
	![f07b82621124af96796e2236074eab6d.png](:/305ae609a637421ea55338d5b812b16b)
- Solution:
	- Find a JMP ESP in the code
	- (Here I finally reverted back to Immunity because I was annoyed by WineDBG. The challenge states you should debug the exe on Unix buuuut whatever)
	- In the main function we find an instruction:
	- ![0e2a09e270b62ccaa3b057aeb7236b1a.png](:/0888f421c40e4e418a2f3c782c07db8e)
- This yields our **return address: F3121731**
- Final command call:
```
python ../../tools/buffer_overflow/overflow_helper.py exploit IP 9999 
-o 524 
-r "F3121731" 
--overflow-char "90" 
--padding 30 
--payload "SHELL_CODE"
```
- Aaand here we are:
![8038a0a7e15fe1810023b7194b981d14.png](:/08688862611344f9bfc1745a534bf333)

## Post Exploitation

- We actually are in a linux environment
- [SCREEN]
- There is a shell script for restarting the brainpan.exe and it belongs to root
	- Unfortunately, the cron job itself is triggered by puck
- After enumerating the system (using linenum.sh here), we find an interesting file (SUID!):
	![4cf369691a52ef9aff583e34eb3ddc61.png](:/df01021d96184958995124ae68c0abb2)
	- Checking it out, it seems vulnerable for yet another overflow exploit:
	![b5636afb2e2a3b7d710c6eae3ab5f0b7.png](:/4f9f797c119a4310aa06767cb452dd92)
	- **Offset: 116**
	- [stop at struggle to put proper bytes into program]