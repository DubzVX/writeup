# Easy CTF 2018 

## Write UP ! 

### Hexedit 

On this Reverse Engineering challenge, we have a ELF 64-bit executable. 
When we execute the program, we can read the sentence "Find the flag". We don't have input password or something like this. 
When I execute my command strace on it, I don't have good information or where to look. 
I decide to see in this with the command strings. 

```sh
strings hexedit | less 
```
Surprise, we can see the flag : 
```sh
__libc_start_main
__gmon_start__
GLIBC_2.2.5
UH-X
UH-X
[]A\A]A^A_
Find the flag!
;*3$"
easyctf{eb04fadf}
GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.3) 4.8.4
.symtab
.strtab
.shstrtab
.interp
```
### In Plain Sight

Description :
```
>I've hidden a flag somewhere at [this](http://blockingthesky.com) site... can you find it?
>Note: There is not supposed to be a website. Nothing is "down". The YouTube link that some of you are finding is unintentional, please ignore it.

**Hint:**

>Dig around and see what you can find
```

This website is not accessible by our browser and the hint said Dig around, something like command line Dig. 
Ok, I will go to execute my tool, DIG : 

```sh
dig TXT blockingthesky.com
```

Output :
```
; <<>> DiG 9.8.2rc1-RedHat-9.8.2-0.62.rc1.el6_9.5 <<>> blockingthesky.com txt
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35257
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;blockingthesky.com.            IN      TXT

;; ANSWER SECTION:
blockingthesky.com.     30      IN      TXT     "_globalsign-domain-verification=kXlECiyonFE_qsQR-8ki6BOIdVru3bzxpwMDZr334_"
blockingthesky.com.     30      IN      TXT     "easyctf{betcha_wish_you_could_have_used_ANY}"

;; Query time: 9 msec
;; SERVER: 213.186.33.99#53(213.186.33.99)
;; WHEN: Wed Feb 21 14:02:14 2018
;; MSG SIZE  rcvd: 180
```
Perfect, we have our flag : 
```
easyctf{betcha_wish_you_could_have_used_ANY}
```
### Programming : Over and Over 

Description :
```
over and over and over and over and over and ...

Given a number N, print the string "over [and over]" such that the string contains N "over"s. There should not be newlines in the string.

For example:

For N = 1, print "over".
For N = 5, print "over and over and over and over and over".

For Python, consider using for and range.

For Java/CXX, consider using a for loop.
Try doing it with while too for practice!
```
I write a code in python, take input, the range on this for, and write over and over and over ... 
```python
X=input()
for N in range(1,X):
    Y=("over" if N else "")+" and over"*(N)
print (Y)
```
### Zippity 

Description :
```
>I heard you liked zip codes! Connect via nc c1.easyctf.com 12483 to prove your zip code knowledge.
```
I start this challenge by connecting and see what is there. 
```sh
nc c1.easyctf.com 12483
```
We can see that : 
```
+======================================================================+
| Welcome to Zippy! We love US zip codes, so we'll be asking you some  |
| simple facts about them, based on the 2010 Census. Only the          |
| brightest zip-code fanatics among you will be able to succeed!       |
| You'll have 30 seconds to answer 50 questions correctly.             |
+======================================================================+

3... 2... 1...  Go!

Round  1 / 50
  What is the water area (m^2) of the zip code 93611? 
```
I decide to search a zipcode database on google. 
I found THIS librairie after a lot research : http://pythonhosted.org/uszipcode/
Intall with this command line : 
```sh
pip install uszipcode
```
And now my code in python : 

```python
#!/usr/bin/python
from uszipcode import ZipcodeSearchEngine
# http://pythonhosted.org/uszipcode/
# install : pip install uszipcode
import socket
import time

### Server ###
hote = "c1.easyctf.com"
port = 12483
### Variables ###
responce = ""
i = 1
zipcodecharset="0123456789"
### Socket connection ###
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((hote,port))

### Find my word in responce ###
def findword(word,contents):
    answers = contents.find(str(word))
    if answers != -1 :
        return word
    else :
        return -1
### Find my zipcode ###
def findzipcode(contents):
    zipcode =""
    code = contents.find("the zip code")
    for y in range(code+12,code+18):
        for carac in zipcodecharset:
            if contents[y] == carac:
                zipcode += carac
                y = code+1
            elif len(zipcode)==5:
                break
            else:
                continue
    return zipcode

def goodword(answers):
    myword =""
    if "longitude" in answers :
        myword = "Longitude"
        return myword
    elif "latitude" in answers:
        myword = "Latitude"
        return myword
    elif "land area" in answers:
        myword = "LandArea"
        return myword
    elif "water area" in answers:
        myword = "WaterArea"
        return myword
    else:
        return -1

def findgoodanswer(answers):
    myword = ""
    myzipcode = 0
    mycity = ""
    myword = goodword(answers)
    myzipcode = findzipcode(answers)
    search = ZipcodeSearchEngine()
    mycity = search.by_zipcode(myzipcode)
    responce = mycity[myword]
    return responce



### Send my responce when I find the good answer ##
def sendresponse(answers):
    ### find good reponce
    responce = str(findgoodanswer(answers))
    ## send
    s.send(responce.encode())
    return 0

def SendAll():
    for i in range(1,51):
        ### reception  ###
        if i == 1 :
            time.sleep(5)
            responce = s.recv(500)
            sendresponse(responce)
            i+=1
        elif i==51:
            responce = s.recv(500)
            print (responce)
            break
        else:
            responce = s.recv(500)
            print (responce)
            sendresponse(responce)
            i+=1
    return 0

if __name__ == '__main__':
    SendAll()
    s.close()

```
### My Letter 
Description :
```
>I got a letter in my email the other day... It makes me feel sad, but maybe it'll make you glad. :(  "myletter.docx"
```
For this challenge, I have a .docx. 
When I open it, I find a fake flag that was made of music from rick astley - never give up ^^. 
I go dirrectly extract file with binwalk and see what I find. 
```sh
binwalk -e myletter.docx 
```
When I look in file, I find an image with the flag. 



