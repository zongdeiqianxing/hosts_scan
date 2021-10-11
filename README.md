# hosts_scan
带有host碰撞的c段扫描工具；对域名文件进行cdn验证并一键爬取未含cdn的c段主机；
扫描结果将保存为csv文件，内涵发现存活的url, status_code, title, copy_right, icp, keyword, r_headers等信息；

## usage:
```
usage: scan.py [-h] [-i IP | -r IPRANGE | -f IPFILE] [-s SAVEPATH] [-T TIMEOUT] [-t THREADING_COUNT] [-k KEYWORD] [-c COOKIE]

By zongdeiqianxing; Email: jshahjk@163.com

optional arguments:
  -h, --help          show this help message and exit
  -i IP
  -r IPRANGE
  -f IPFILE
  -s SAVEPATH         须给定csv格式
  -T TIMEOUT
  -t THREADING_COUNT
  -k KEYWORD          根据关键词检测响应包内匹配个数
  -c COOKIE
```

## 报告文件
![image](example.png)
