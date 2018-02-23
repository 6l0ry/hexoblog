How to contribute
===

## 環境設置
- 確認 nodejs 以及 npm 已安裝
- 安裝 hexo-cli
`$ sudo npm install hexo-cli -g`
- 基本套件設定


## 如何發布自己的文章

- Fork 此 repo
- 在自己的 repo 上做更改
- 送 PR !



## Hexo 基本指令
`hexo n (hexo new)` 新增文章
`hexo g (hexo generate)` 渲染, 產出網站
`hexo d (hexo deploy)` 發布網站 (github by default)
`hexo s [--debug] (hexo server [--debug])` 布置內網網站(--debug 會顯示http status)

## 製作文章
網站會依照語言做分賴

```
繁體中文 -> zh-tw
英文 -> en
簡體中文 -> zh-hans
```

這需要再執行`hexo n`時多加上`--type`參數
ex. `hexo n ASIS-2017-writeup --lang zh-tw`


在MD檔內會有hexo特有的標頭檔`(Front-Matter)`
標頭檔內須調整的設定為`tags`, `categories`

`tags`即為文章標籤

`categories`會依照填入的順序進行分類
ex. 
```
categories:
    - writeup
    - ais3
    - pwn
```
產出的結果為
`writeup -> ais3 -> pwn`
請在編輯`categories`時格外小心

程式碼高亮需使用以下格式`(lang可依使用程式語言調整, 在此用python作範例)`
```
{% codeblock lang:python %}
....
{% endcodeblock %}
```

其餘依照Markdown寫作即可



<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="創用 CC 授權條款" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br />本著作係採用<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">創用 CC 姓名標示-相同方式分享 4.0 國際 授權條款</a>授權.
> 2017.09.15 racterub
