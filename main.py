# coding:utf-8
import requests
import argparse
import os
import re
import threading
import socket
import platform
import csv
from IPy import IP
from queue import Queue
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


HEADERS = { 'Host': '',
            'User-Agent': 'Mozilla/5.0 (Macintosh; (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            'Cookie': ''
            }
PORTS = [80, 81, 82, 88, 7001, 8000, 8001, 8002, 8008, 8088, 8443, 9000, 10000, 10001, 10080,]
TIMEOUT = 5
KEYWORD = ''
SAVEPATH = ''
THREAD_COUNT = 20

syst = platform.system()
PLATFORM = 'windows' if syst == "Windows" else ''


class GetArgs:
    def __init__(self):
        self.args = self.parse()

        global TIMEOUT, KEYWORD, SAVEPATH, THREAD_COUNT
        TIMEOUT = self.args.timeout if self.args.timeout != 5 else 5
        SAVEPATH = self.args.savepath if self.args.savepath else 'result.csv'
        THREAD_COUNT = self.args.threading_conut if self.args.threading_count != 20 else 20
        KEYWORD = self.args.keyword
        if self.args.cookie:
            HEADERS['Cookie'] = self.args.cookie
        else:
            del HEADERS['Cookie']
        # print(self.parse())

    def parse(self):
        parser = argparse.ArgumentParser(description='''
        By zongdeiqianxing; Email: jshahjk@163.com
        ''')
        group = parser.add_mutually_exclusive_group()

        group.add_argument('-i', action="store", dest="ip",)
        group.add_argument('-r', action="store", dest="iprange", type=str,)
        group.add_argument('-f', action="store", dest="ipfile", type=str)
        parser.add_argument('-s', action="store", required=False, dest="savepath", type=str, default='', help='须给定csv格式')
        parser.add_argument('-T', action="store", required=False, type=int, dest="timeout", default=5)
        parser.add_argument('-t', action="store", required=False, type=int, dest="threading_count", default=20)
        parser.add_argument('-k', action="store", required=False, type=str, dest="keyword", default='', help='根据关键词检测响应包内匹配个数')
        parser.add_argument('-c', action="store", required=False, type=str, dest="cookie", default='')
        args = parser.parse_args()
        return args


class GetTargets:
    def __init__(self):
        self.args = GetArgs().args
        self.ips_queue = Queue()
        self.domains_queue = Queue()

    def isIP(self, target):
        pattern = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
        if pattern.match(target):
            return True

    def nslookup(self, target):
        Ip = ''
        cdns = ['cdn', 'kunlun', 'bsclink.cn', 'ccgslb.com.cn', 'dwion.com', 'dnsv1.com', 'wsdvs.com', 'wsglb0.com',
                'lxdns.com', 'chinacache.net.', 'ccgslb.com.cn', 'aliyun']

        # 域名中存在cdn的字符串 则判定
        dns = ['9.9.9.9', '223.5.5.5', '1.2.4.8']   # IBM 阿里云 中国互联网络信息中心
        for _dns in dns:
            result = os.popen('nslookup {t} {d}'.format(t=target, d=_dns)).read()
            if 'timed out.' in result:
                continue

            name = re.findall('Name|名称:.+?\n', result)
            if name:
                for cdn in cdns:
                    if cdn in name:
                        return False

            # 根据不同dns解析出来的ip地址如果不一样，则判定
            ip = '1'
            if PLATFORM:
                if 'Address:' in result.split('\n')[-1] and result.split('\n')[-1].count('.') == 3:
                    ip = result.split('\n')[-1].split(':')[1].strip()
                elif result.split('\n')[-3].count('.') == 3:
                    ip = result.split('\n')[-3].strip()
            else:
                ip = re.findall('Address:[^#]+?\n', result)
                if ip:
                    ip = ip[0].split(':')[1].strip()
            if Ip:
                if ip != Ip:
                    return False
            else:
                Ip = ip

        return True if IP else False

    def setTargets(self):
        if self.args.ip:
            if self.isIP(self.args.ip):
                self.ips_queue.put(self.args.ip)
        if self.args.ipfile:
            print('读取文件并解析域名，判断是否存在cdn中...')
            with open(self.args.ipfile, 'r', encoding='utf8') as f:
                for line in f.readlines():
                    line = line.strip()
                    if self.isIP(line):
                        self.ips_queue.put(line)
                    else:
                        if self.nslookup(line):
                            self.domains_queue.put(line)

        print('发现ip目标{}个及无cdn域名{}个'.format(self.ips_queue.qsize(), self.domains_queue.qsize()))
        return self.ips_queue, self.domains_queue


class Scan:
    def __init__(self):
        self.ips_queue, self.domains_queue = GetTargets().setTargets()
        self.c_ips = Queue()
        self.data = []

    def threading_requests(self):
        target, domain = '', ''
        while not self.ips_queue.empty() or not self.domains_queue.empty():
            if not self.ips_queue.empty():
                target = socket.getaddrinfo(self.ips_queue.get(), None)[0][4][0]
            elif not self.domains_queue.empty():
                domain = self.domains_queue.get()
                target = socket.getaddrinfo(domain, None)[0][4][0]

            for ip in IP(target[:target.rindex('.')]+'.0/24'):
                for port in PORTS:
                    self.c_ips.put('http://{}:{}'.format(ip, port))

        print('开始扫描c段：')
        for i in range(THREAD_COUNT):
            t = threading.Thread(target=self.run)
            t.start()

    def run(self):
        while not self.c_ips.empty():
            url = self.c_ips.get()
            try:
                headers = HEADERS
                host = urlparse(url).netloc.split(':')[0]
                headers['Host'] = str(host)
                response = requests.get(url=url, headers=headers, timeout=TIMEOUT, verify=False)
                if response.text:
                    response.encoding = 'utf-8'
                    r = re.findall("<title>([\s\S]+?)</title>", response.text)
                    title = r[0] if r else ''

                    r = re.findall("(?:版权所有|Copyright).+?<", response.text)
                    copy_right = r[0][:-1] if r else ''

                    r = re.findall(".ICP备.+?<", response.text)
                    icp = r[0][:-1] if r else ''

                    status_code = response.status_code
                    r_headers = response.headers
                    keyword = response.text.count(KEYWORD) if KEYWORD else ''

                    print([url, status_code, title, copy_right, icp, keyword, r_headers])
                    self.data.append([url, status_code, title, copy_right, icp, keyword, r_headers])
            except requests.exceptions.ConnectionError:
                pass
            except Exception as e:
                print(e)
                self.output()

    def output(self):
        with open(SAVEPATH, 'w', encoding='utf-8', newline='') as f:
            f_csv = csv.writer(f)
            for line in self.data:
                f_csv.writerow(line)


if __name__ == '__main__':
    s = Scan()
    s.threading_requests()
    s.output()


