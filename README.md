# webanalyzer
Web指纹识别工具，使用Python3.6以上版本运行。基于https://github.com/webanalyzer/webanalyzer.py修改，主要修改以下几点：

- 添加支持代理、多线程
- 输出结果包含匹配详情。即什么正则匹配了响应body，或md5匹配了body等
- 按Ctrl+C后输出已识别到的结果

## 安装
```shell script
git clone --depth 1 https://github.com/Ovi3/webanalyzer.git
cd webanalyzer
python3 -m pip install -r requirements.txt
python3 webanalyzer.py -h
```


## 使用

第一次运行程序可从https://github.com/webanalyzer/rules下载指纹规则到项目根目录的./rules目录下：
``` sh
python3 webanalyzer.py --update
```

./rules目录为默认的规则目录，该目录下所有以.json结尾的文件都视为规则文件。./rules/custom/目录存用户添加的规则，执行--update时不会覆盖custom目录


使用方法:

``` sh
python webanalyzer.py -h
Usage: webanalyzer.py [OPTIONS]

Options:
  -u, --url TEXT                  Target
  -d, --directory TEXT            Rules directory, default ./rules
  -a, --aggression INTEGER RANGE  Aggression mode, default 0
  -U, --user-agent TEXT           Custom user agent
  -H, --header TEXT               Pass custom header LINE to serve
  -x, --proxy TEXT                specify proxy
  -t, --max-threads INTEGER       Max thread count, default 20
  -v, --verbose INTEGER RANGE     Verbose level, default 2
  -r, --rule TEXT                 Specify rule
  --disallow-redirect             Disallow redirect
  --list-rules                    List rules
  --update                        Update rules
  -h, --help                      Show this message and exit.
```
- verbose参数指定日志level。verbose越高，输出越详细，默认为2。各值对应的level：
  - 0 - CRITICAL
  - 1 - ERROR
  - 2 - WARNING
  - 3 - INFO
  - 4 - DEBUG
- aggression参数：
  - 值为0时，只发送两个请求：用户指定url，和/favicon.ico。
  - 值为1时，还会主动请求custom规则里包含的url，并进行规则匹配
  - 值为2时，主动请求所有规则里包含的url，并进行规则匹配



例子:

```sh
python webanalyzer.py -u "http://blog.fatezero.org"
[
    {
        "name": "Fastly",
        "detail": "regex \".*\" match headers[x-fastly-request-id] of http://blog.fatezero.org",
        "origin": "wappalyzer"
    },
    {
        "name": "GitHub Pages",
        "detail": "regex \".*\" match headers[x-github-request-id] of http://blog.fatezero.org",
        "origin": "wappalyzer"
    },
    {
        "name": "Hexo",
        "detail": "regex \"Hexo(?: v?([\\d.]+))?\" match meta[generator] of http://blog.fatezero.org",
        "version": "3.9.0",
        "origin": "wappalyzer"
    },
    {
        "name": "Varnish",
        "detail": "regex \"varnish(?: \\(Varnish/([\\d.]+)\\))?\" match headers[via] of http://blog.fatezero.org",
        "origin": "wappalyzer"
    },
    {
        "name": "HTML5",
        "detail": "regex \"(?i-mx:<!DOCTYPE html>)\" match body of http://blog.fatezero.org",
        "origin": "whatweb"
    },
    {
        "name": "MetaGenerator",
        "detail": "regex \"(?i-mx:<meta[^>=]+name[\\s]*=[\\s]*[\"|']?generator[\"|']?[^>=]+content[\\s]*=[\\s]*\"([^\"'>]+)\")\" match body of http://blog.fatezero.org",
        "origin": "whatweb"
    },
    {
        "name": "OpenSearch",
        "detail": "regex \"(?i-mx:<link[^>]+type[\\s]*=[\\s]*[\"']?application\\/opensearchdescription\\+xml['\"]?[^>]+href[\\s]*=[\\s]*[\"']([^'^\"^>]+)[\"'][^>]*>)\" match body of http://blog.fatezero.org",
        "origin": "whatweb"
    },
    {
        "name": "PoweredBy",
        "detail": "regex \"(?i-mx:powered[ -]?by[ ]?([^\\s<>'\".]+))\" match body of http://blog.fatezero.org",
        "origin": "whatweb"
    },
    {
        "name": "Script",
        "detail": "regex \"(?i-mx:<script(\\s|>))\" match body of http://blog.fatezero.org",
        "origin": "whatweb"
    },
    {
        "name": "Via-Proxy",
        "detail": "regex \"(?-mix:^.*$)\" match headers[via] of http://blog.fatezero.org",
        "origin": "whatweb"
    },
    {
        "name": "Ruby on Rails",
        "origin": "implies"
    }
]

```

指定某个rule测试
``` sh
python webanalyzer.py -u "http://blog.fatezero.org" -r ./rules/wappalyzer/hexo.json
{
    "name": "Hexo",
    "detail": "regex \"Hexo(?: v?([\\d.]+))?\" match meta[generator] of http://blog.fatezero.org",
    "version": "3.9.0",
    "origin": "test"
}
```

输出结果说明
- name：组件名
- version：版本号
- detail：匹配详情。匹配详情不考虑condition字段，只输出最后一个匹配到的规则，即matches数组里最后一个匹配的（见下方“规则编写”）
- origin：规则来源


## 规则编写
规则文件为json格式，文件名以.json结尾。参考：https://github.com/webanalyzer/rules/blob/master/README.md

例子:

```json
{
    "name": "wordpress",
    "author": "fate0",
    "version": "0.1.0",
    "description": "wordpress 是世界上最为广泛使用的博客系统",
    "website": "http://www.wordpress.org/",
    "matches": [],
    "condition": "0 and (1 and not 2)",
    "implies": "PHP",
    "excludes": "Apache"
}
```

描述:

| FIELD       | TYPE   | DESCRIPTION  | EXAMPLE                                    | REQUIRED |
|-------------|--------|--------------|--------------------------------------------|----------|
| name        | string | 组件名称     | `wordpress`                                | true     |
| author      | string | 作者名       | `fate0`                                    | false    |
| version     | string | 插件版本     | `0.1.0`                                    | false    |
| description | string | 组件描述     | `wordpress 是世界上最为广泛使用的博客系统` | false    |
| website     | string | 组件网站     | `http://www.wordpress.org/`                | false    |
| matches     | array  | 规则         | `[{"regexp": "wordpress"}]`                | true     |
| condition   | string | 规则组合条件 | `0 and (1 and not 2)`                        | false    |
| implies     | string/array | 依赖的其他组件 | `PHP`                               | false    |
| excludes    | string/array | 肯定不依赖的其他组件 | `Apache`                       | false    |

补充说明
- version字段：不是指指纹匹配到的组件的版本，可以不必理会
- implies字段：当匹配到该规则时会将implies字段的内容作为加到指纹匹配结果里
- excludes字段：当匹配到该规则时会将excludes字段的内容从指纹匹配结果里排除掉


### 规则信息
matches数组里存储规则信息

例子:

```
[
    {
        "name": "rule name"
        "search": "all",
        "text": "wordpress"
    }
]
```

描述:

| FIELD      | TYPE   | DESCRIPTION                                                             | EXAMPLE                            |
|------------|--------|-------------------------------------------------------------------------|------------------------------------|
| name       | string | 规则名称                                                                | `rulename`                         |
| search     | string | 搜索的位置，可选值为 `all`, `headers`, `title`, `body`, `script`, `cookies`, `headers[key]`, `meta[key]`, `cookies[key]`| `body`                              |
| regexp     | string | 正则表达式                                                              | `wordpress.*`                      |
| text       | string | 明文搜索                                                                | `wordpress`                        |
| version    | string | 匹配的版本号                                                            | `0.1`                              |
| offset     | int    | regexp 中版本搜索的偏移（从0开始）                                       | `1`                                |
| certainty  | int    | 确信度                                                                  | `75`                               |
| md5        | string | 目标文件的 md5 hash 值                                                  | `beb816a701a4cee3c2f586171458ceec` |
| url        | string | 需要请求的 url                                                          | `/properties/aboutprinter.html`    |
| status     | int    | 请求 url 的返回状态码，默认是 200                                       | `400`                              |



## 检测逻辑

* 如果 match 中存在 url 字段，plugin 是属于 custom 类型且 `aggression` 开启，则请求 url 获取相关信息
* 根据 search 字段选取搜索位置
* 根据 regexp/text 进行文本匹配，或者 status 匹配状态码，或者 md5 匹配 body 的 hash 值
* 如果是用regexp匹配的且正则存在`(?P<version>)`命名组，直接从该组里获取版本号；如果存在 offset 就从 regexp 中匹配出版本；如果 match 中存在 version 就表明规则直接出对应版本；
* 如果 rule 中存在 condition，则根据 condition 判断规则是否匹配，默认每个 match 之间的关系为 `or`




