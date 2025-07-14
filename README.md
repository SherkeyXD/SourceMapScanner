# SourceMap 泄露扫描器

利用 [`playwright`](https://playwright.dev/) 访问网站，然后收集所有 js 并查看是否有 map 文件


## 用法

安装依赖

`pip install -r requirements.txt` 或是 `uv sync`

安装 playwright 浏览器

`playwright install`

运行扫描器程序

`python scanner.py -h`

```
usage: scanner.py [-h] (-u URL | -f FILE) [-t TIMEOUT] [-v] [--deep-scan] [-c MAX_CONCURRENT] [-b] [-d DIR] [-s]

🔍 Source Map Scanner - Advanced vulnerability scanner for source map leakages (scans current domain only)

options:
  -h, --help            show this help message and exit
  -u, --url URL         Target website URL to scan
  -f, --file FILE       File containing URLs to scan (one URL per line)
  -t, --timeout TIMEOUT
                        Request timeout in seconds (default: 15)
  -v, --verbose         Enable verbose logging
  --deep-scan           Enable deep scan with additional detection patterns
  -c, --max-concurrent MAX_CONCURRENT
                        Maximum concurrent requests (default: 10)
  -b, --show-browser    Don't run browser in headless mode (use this flag to show browser)
  -d, --download DIR    Download vulnerable JS and source map files to specified directory
  -s, --strict          Strict mode: validate source map files have proper JSON structure

Example: python scanner.py -u https://example.com -v -d ./downloads --strict
```

## 后续利用

获取 map 文件后，可以利用 [davidkevork/reverse-sourcemap](https://github.com/davidkevork/reverse-sourcemap) 将源码反编译出来