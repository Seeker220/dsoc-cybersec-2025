# Writeup for DSOC Cybersec CTF Week 1

## 1. Hidden in the Crowd

```bash
ctfuser@643070aed338:~$ ls -la
total 4044
dr-xr-xr-x 1 ctfuser ctfuser 24576 Jun  4 13:36 .
drwxr-xr-x 1 root    root     4096 Jun  4 13:36 ..
-rw-r--r-- 1 ctfuser ctfuser   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 ctfuser ctfuser  3771 Feb 25  2020 .bashrc
-r--r--r-- 1 root    root       38 Jun  4 13:36 .flag
-rw-r--r-- 1 ctfuser ctfuser   807 Feb 25  2020 .profile
-r--r--r-- 1 root    root       28 Jun  4 13:36 06kaB
-r--r--r-- 1 root    root       28 Jun  4 13:36 09SCP
-r--r--r-- 1 root    root       28 Jun  4 13:36 0C6j3
-r--r--r-- 1 root    root       28 Jun  4 13:36 0EmL5
-r--r--r-- 1 root    root       28 Jun  4 13:36 0W9YQ
-r--r--r-- 1 root    root       28 Jun  4 13:36 0ei0t
-r--r--r-- 1 root    root       28 Jun  4 13:36 0pMrQ
-r--r--r-- 1 root    root       28 Jun  4 13:36 0tleW
-r--r--r-- 1 root    root       28 Jun  4 13:36 0u04k
.....
```
A hidden flag file is found among many other files.
```bash
ctfuser@643070aed338:~$ cat .flag
dcCTF{h1dd3n_f1l3s_4r3_n07_s0_h1dd3n}
```

## 2. Welcome Agent

```bash
ctfuser@b83857127209:~$ ls
flag.txt
ctfuser@b83857127209:~$ cat flag.txt
dcCTF{w3lc0me_t0_7h3_m4tr1x}
```

## 3. Process Hunter

```bash
ctfuser@16abf758d0fc:~$ ls
readme.txt
ctfuser@16abf758d0fc:~$ cat readme.txt
A process is running with a flag in its command line. Find it!
ctfuser@16abf758d0fc:~$ ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2616  1428 ?        Ss   14:03   0:00 /bin/sh -c /usr/sbin/sshd && sleep --flag=dcCTF{ps_aux_r3v34l5_4ll} 99999999 & /usr/sbin/sshd -D
root           8  0.0  0.0  12196  7272 ?        S    14:03   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root          11  0.0  0.1  13404  8392 ?        Ss   14:04   0:00 sshd: ctfuser [priv]
ctfuser       22  0.0  0.0  13404  5728 ?        R    14:04   0:00 sshd: ctfuser@pts/0
ctfuser       23  0.0  0.0   6000  3792 pts/0    Ss   14:04   0:00 -bash
ctfuser       29  0.0  0.0   7652  2860 pts/0    R+   14:04   0:00 ps aux
```

## 4. Binary Directory

We were given a .tar.gz archive, upon extracting which we got a directory structure having files [a-x]\/((:?[01]\/){8})tof , each of which is either "0" or "1". Now top directory "a" has only 1 tof file which is "1". This means the dir structure of "1" tof of a will give the first letter of the flag.
```python3
import os
cw = os.getcwd() + "/chal/"
for i in "abcdefghijklmnopqrstuvwx":
    for dirpath, dirnames, filenames in os.walk(cw + i):
        for filename in filenames:
            with open(dirpath + "/" + filename, "r") as file:
                if file.read() == "1":
                    print(dirpath + "/" + filename)
```
This gives output
```
/home/seeker220/ctf-prac/Binary Directory/chal/a/0/1/1/0/0/1/0/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/b/0/1/1/0/0/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/c/0/1/0/0/0/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/d/0/1/0/1/0/1/0/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/e/0/1/0/0/0/1/1/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/f/0/1/1/1/1/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/g/0/1/1/1/0/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/h/0/1/1/0/0/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/i/0/1/1/1/0/0/1/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/j/0/0/1/1/0/0/0/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/k/0/1/1/1/0/0/0/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/l/0/0/1/1/0/1/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/m/0/0/1/1/0/0/0/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/n/0/1/1/0/1/1/1/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/o/0/1/1/0/0/1/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/p/0/1/0/1/1/1/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/q/0/0/1/1/0/0/0/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/r/0/1/1/1/0/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/s/0/1/0/1/1/1/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/t/0/1/1/0/0/0/1/1/tof
/home/seeker220/ctf-prac/Binary Directory/chal/u/0/0/1/1/0/0/0/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/v/0/0/1/1/0/0/0/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/w/0/1/1/0/1/1/0/0/tof
/home/seeker220/ctf-prac/Binary Directory/chal/x/0/1/1/1/1/1/0/1/tof
```
and then doing a quick find and replace in mousepad, we get
```
01100100
01100011
01000011
01010100
01000110
01111011
01110011
01100011
01110010
00110001
01110000
00110111
00110001
01101110
01100111
01011111
00110001
01110011
01011111
01100011
00110000
00110000
01101100
01111101
```
plugging on to [GHCQ](https://gchq.github.io) using `From Binary`, we get the flag `dcCTF{scr1p71ng_1s_c00l}`

## 5. Log Explore

Running the logGen programme produces a log file.
```bash
┌──(seeker220㉿seeker220)-[~/ctf-prac/Log Explore]
└─$ ./logGen    
Log file generated.
┌──(seeker220㉿seeker220)-[~/ctf-prac/Log Explore]
└─$ ls
logGen  logGen.cpp  log.txt  readme.md
┌──(seeker220㉿seeker220)-[~/ctf-prac/Log Explore]
└─$ cat log.txt
Log checkpoint at offset 0 MB: All systems OK.
Log checkpoint at offset 500 MB: All systems OK.
Log checkpoint at offset 1000 MB: All systems OK.
Log checkpoint at offset 1500 MB: All systems OK.
Log checkpoint at offset 2000 MB: All systems OK.
!! ALERT: hidden flag --> dcCTF{b1G_L0g}
Log checkpoint at offset 3000 MB: All systems OK.
^C
```

## 6. Locked Vault

Unarchiving the .tar.gz archive gives 3 files.
```bash
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault]
└─$ tar -xzf LockedVault.tar.gz
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault]
└─$ ls
LockedVault  LockedVault.tar.gz
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault]
└─$ cd LockedVault
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ ls
README.txt  step1.sh  step2.sh  step3.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ cat README.txt 
LOCKED VAULT CHALLENGE

You have 3 scripts but they have restrictive permissions:
- step1.sh: Cannot be read (need to fix permissions to see the password)
- step2.sh: Cannot be executed (need to make executable and use password from step1)  
- step3.sh: Cannot be read (need to fix permissions and use key from step2)

Each script checks for the correct input from the previous step.
Even if you bypass permissions with sudo, you still need to solve each step properly!

Start by fixing permissions on step1.sh and reading it.
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ ls -l step1.sh            
---------- 1 seeker220 seeker220 330 Jun  2 17:40 step1.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ chmod +r step1.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ chmod +x step1.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ ./step1.sh 
Step 1 complete!
Password found: unlock123
Now make step2.sh executable and run it with this password!
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ chmod +x step2.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ ./step2.sh                       
Enter the password from step1:
unlock123
Correct! Moving to final step...
Key for step3: final_key_456
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ chmod +x step3.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ ls -l step3.sh
---x--x--x 1 seeker220 seeker220 498 Jun  2 17:40 step3.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ chmod +r step3.sh
┌──(seeker220㉿seeker220)-[~/ctf-prac/LockedVault/LockedVault]
└─$ ./step3.sh       
Enter the key from step2:
final_key_456
Vault unlocked!
Flag: dcCTF{y0u_4r3_4_p3rm1ss10n_h0ckcr_n0w}
```

## 7. Git Gud

Unzipping gives a directory
```bash
┌──(seeker220㉿seeker220)-[~/ctf-prac/Git Gud]
└─$ unzip git_forensics_challenge.zip
┌──(seeker220㉿seeker220)-[~/ctf-prac/Git Gud]
└─$ ls
git_forensics_challenge  git_forensics_challenge.zip
┌──(seeker220㉿seeker220)-[~/ctf-prac/Git Gud]
└─$ cd git_forensics_challenge
┌──(seeker220㉿seeker220)-[~/ctf-prac/Git Gud/git_forensics_challenge]
└─$ ls -la        
total 16
drwxr-xr-x 3 seeker220 seeker220 4096 Jun  2 20:22 .
drwxrwxr-x 3 seeker220 seeker220 4096 Jun  4 23:39 ..
drwxr-xr-x 7 seeker220 seeker220 4096 Jun  2 20:22 .git
-rw-r--r-- 1 seeker220 seeker220   51 Jun  2 20:22 README.md
┌──(seeker220㉿seeker220)-[~/ctf-prac/Git Gud/git_forensics_challenge]
└─$ cat README.md             
This is a sample README.
Just some boring changes.
┌──(seeker220㉿seeker220)-[~/ctf-prac/Git Gud/git_forensics_challenge]
└─$ git log -p    
commit 1020cf6b231c9c2702a62e745c119bc6f7938970 (HEAD -> master)
Author: Z3R0C1PH3R <Z3R0C1PH3R@protonmail.com>
Date:   Mon Jun 2 20:22:49 2025 +0530

    Update README again

diff --git a/README.md b/README.md
index 9297bd6..a2c69dc 100644
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 This is a sample README.
+Just some boring changes.

commit 1e2d1d684ee24693070677e9620ea6afb4fa31df
Author: Z3R0C1PH3R <Z3R0C1PH3R@protonmail.com>
Date:   Mon Jun 2 20:22:49 2025 +0530

    Remove flag

diff --git a/flag.txt b/flag.txt
deleted file mode 100644
index e58e971..0000000
--- a/flag.txt
+++ /dev/null
@@ -1 +0,0 @@
-dcCTF{g17_0bj3ct5_n3v3r_d13}

commit 5750476ca64e3a900c8b97f7cbae2578c79955b8
Author: Z3R0C1PH3R <Z3R0C1PH3R@protonmail.com>
Date:   Mon Jun 2 20:22:49 2025 +0530

    Add sensitive file

diff --git a/flag.txt b/flag.txt
new file mode 100644
index 0000000..e58e971
--- /dev/null
+++ b/flag.txt
@@ -0,0 +1 @@
+dcCTF{g17_0bj3ct5_n3v3r_d13}

commit 63497d90d523d389530e56d18e4b285e31ad6646
Author: Z3R0C1PH3R <Z3R0C1PH3R@protonmail.com>
Date:   Mon Jun 2 20:22:49 2025 +0530

    Initial commit

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..9297bd6
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+This is a sample README.
```

## 8. Dumpster Diver

Run the program on another terminal
```bash
┌──(seeker220㉿seeker220)-[~/ctf-prac/Dumpster Diver]
└─$ ls
program  readme.md
┌──(seeker220㉿seeker220)-[~/ctf-prac/Dumpster Diver]
└─$ cat readme.md      
The c++ code that created that ran forever. Just had to take a memory dump of this to get the flag
┌──(seeker220㉿seeker220)-[~/ctf-prac/Dumpster Diver]
└─$ ./program   
Running forever...
```
and on a different terminal,
```bash
┌──(seeker220㉿seeker220)-[~]
└─$ ps -aux | grep program
seeker2+   41222  0.0  0.0   6136  2984 pts/0    S+   23:50   0:00 ./program
seeker2+   41646  0.0  0.0   6456  1972 pts/1    S+   23:50   0:00 grep --color=auto program
┌──(seeker220㉿seeker220)-[~]
└─$ cd ctf-prac/Dumpster\ Diver
┌──(seeker220㉿seeker220)-[~/ctf-prac/Dumpster Diver]
└─$ sudo gcore 41222                 
[sudo] password for seeker220: 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f70a0118839 in syscall () from /lib/x86_64-linux-gnu/libc.so.6
Saved corefile core.41222
[Inferior 1 (process 41222) detached]
┌──(seeker220㉿seeker220)-[~/ctf-prac/Dumpster Diver]
└─$ strings core.41222 | grep dcCTF
dcCTF{m3m0ry_dump_fl4g}B
```

## 9. Bring Back from the Dead

I used photorec to recover the deleted image
```bash
┌──(seeker220㉿seeker220)-[~/ctf-prac]
└─$ cd 'Bring Back from the Dead/'
┌──(seeker220㉿seeker220)-[~/ctf-prac/Bring Back from the Dead]
└─$ ls
challenge.img
┌──(seeker220㉿seeker220)-[~/ctf-prac/Bring Back from the Dead]
└─$ sudo photorec challenge.img  
[sudo] password for seeker220: 
PhotoRec 7.2, Data Recovery Utility, February 2024
Christophe GRENIER <grenier@cgsecurity.org>
┌──(seeker220㉿seeker220)-[~/ctf-prac/Bring Back from the Dead]
└─$ ls
challenge.img  photorec.se2  recup_dir.1
https://www.cgsecurity.org
```
and looking inside recup_dir.1, we recover the flag from a png image `dcCTF{f1l3_s0rc3r0r}`

## 10. Event Digger

Since I couldn't complete this (js is not my primary lang), I'll tell upto where I went.
We are given base64 encrypted string `dmFyIGV2ZW50cyA9IFs2OCwgNjcsIDY3LCA4NCwgNzAsIDIxOSwgNzQsIDgzLCAxODksIDcwLCA0 OSwgNjUsIDcxLCAyMjFdCg==`
decrypting which gives `var events = [68, 67, 67, 84, 70, 219, 74, 83, 189, 70, 49, 65, 71, 221]`
which is js.
Now I tried
```python3
events = [68, 67, 67, 84, 70, 219, 74, 83, 189, 70, 49, 65, 71, 221]
print(''.join(chr(e) if e < 128 else chr(e-96) for e in events))
print(''.join(chr(e) if e < 128 else chr(e^128) for e in events))
```
which printed
```
DCCTF{JS]F1AG}
DCCTF[JS=F1AG]
```
and I tried to match the format of the other flags, so I tried `dcCTF{js_f1ag}` which didn't work :(
This actually had to be mapped from [here](https://www.toptal.com/developers/keycode/table)

