---
title: CCNS Wargame (web)
tags:
  - Write-up
  - CCNS
  - web
categories:
  - Write-up
  - CCNS
  - web
lang: zh-tw
date: 2018-03-12 15:00:51
author: hurosu
---


## Log is important

看瀏覽器中的輸出資料得知flag
`CCNS{53lf_x55}`

## Frontend engineer

F12原始碼中 題目註解藏flag

{% codeblock lang:html %}
<span class="chal-desc"><h4>誠徵前端工程師</h4>
<p><strong>需求：</strong></p>
<ol><li>熟悉 html, css</li><li>無經驗可</li><li>有寫註解的習慣</li></ol>
<p><strong>待遇：</strong></p>
<ul><li>５０點</li></ul>


<!-- CCNS{fr0n73nd_5uck5} -->
{% endcodeblock %}

## 妹妹的臉書帳號

一個登入系統 題目給了username了 直接試著Sqlinjection
username: imouto
password: 'or'1'='1
得到flag
`CCNS{YO_HAVE_NO_SISTER}`

## ㄌㄌㄎ

從原始碼中得到一串script
`<script src="source.js"></script>`
直接帶入網址
得到flag

`CCNS{1o1i_5aik0u_87euihkjr484uirhgur48terheirqo34895tur484uirhgur48terhioo43895tyuhieiwo493r89t4uihjefwio4r8uguihererheirqo34pw4uihp49tiueghrulw485tygehur484tugiq34quoireugt82q3pwreuw485tygehur484tugiq34quoireugt82eghpt87tq38ihwergi3uhto8fui3ythow83hp49tiueghrulw485tygehur484tugiq34quoireugt82q3pwreui4rhofw8ueirhfow873uiergtw8o48t7yololiloliloli}`
沒錯 就是那麼長
