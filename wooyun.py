#!/usr/bin/python
# -*- coding: utf-8 -*-
# author zeck.tang

import requests
import re
import time
import cookielib
import datetime

from bs4 import BeautifulSoup

"""
程序功能是从wooyun获取漏洞列表信息
随时可以跑,每次会跑到上一次开始的地方
(由于漏洞列表的日期是无规律的所以使用id进行边界匹配)
如果是第一次跑,会默认跑到第20页,如果需要更多可以自行修改PAGE_MAX
跑的内容存储在buglist.txt
匹配标的的内容存储在targetlist.txt
(匹配标的可以自行修改,中文请注意转码)
"""

# 一次循环读取页数限制
PAGE_MAX = 20

# 存边界id文件
CODE_FILENAME = 'wooyun_code.txt'
# 存结果list文件
LIST_FILENAME = 'wooyun_buglist.txt'
# 存标的list文件
TARGET_FILENAME = 'wooyun_targetlist.txt'

headers = {
    'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
    'Accept-Encoding': 'gzip, deflate',
    'Connection' : 'keep-alive',
    'Cookie': '__cfduid=df9f8a9e242cc626dc8cf59339b5201351459410747; PHPSESSID=j6ariffo2vgqebt3lef8avtp73; Hm_lvt_c12f88b5c1cd041a732dea597a5ec94c=1459410749; Hm_lpvt_c12f88b5c1cd041a732dea597a5ec94c=1459410749; bdshare_firstime=1459410749057',
    'Host' : "www.wooyun.org",
    'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:44.0) Gecko/20100101 Firefox/44.0"
}

def doGet():
    page = 1
    codeStrEnd = ''
    # 用于结束while循环
    breakTag = 0
    # 用于判断本次while循环的进入第一条
    flag = 0
    code = open(CODE_FILENAME,'w')
    code.close()
    while breakTag == 0 :
        targetUrl = 'http://www.wooyun.org/bugs/page/%s' % page
        print targetUrl
        cookies = cookielib.MozillaCookieJar('cookies.txt')
        content = requests.get(targetUrl ,headers = headers, cookies = cookies)
        content.encoding = 'utf-8'
        #dataFile = open('wooyun.txt', 'w')
        #dataFile.write(content.text.encode('utf-8'))
        #dataFile.close()

        pattern = re.compile('.*?class="listTable">(.*?)</table>.*?',re.S)
        tempStr = re.findall(pattern,content.text.encode('utf-8'))
        #print tempStr
        result = open(LIST_FILENAME, 'a')
        soup = BeautifulSoup(tempStr[0].decode('utf-8'),'html.parser')
        todayTime = datetime.date.today()
        target = open(TARGET_FILENAME,'a')
        code = open(CODE_FILENAME,'r')
        codeStr = code.read()
        code.close()

        for tag in soup.findAll(True):
            if tag.name =='a' and tag.has_attr('href') and ''.join(tag['href']).find('wooyun') > 0 and ''.join(tag['href']).find('#') <= 0:
                if codeStr != '':
                    if codeStr == ''.join(tag['href']).split('-')[2] :
                        # 匹配到上次一致的id,终端本次数据采集
                        print 'codeStr bingo'
                        if codeStrEnd == '':
                            codeStrEnd = ''.join(tag['href']).split('-')[2]
                        breakTag = 1
                        print '%s : %s  page : %s  --> loop end ' % (codeStrEnd,codeStr,page)
                        break
                    else :
                        # 记录本次开始的id,如果是第一次进入while循环
                        if flag == 0 :
                            codeStrEnd = ''.join(tag['href']).split('-')[2]
                            flag = 1
                else :
                    # 第一次跑程序或code内容被清空的情况,需要记录本次开始的id
                    if flag ==0:
                        codeStrEnd = ''.join(tag['href']).split('-')[2]
                        flag = 1
                # 截取title 和 link
                res = ('%s : http://www.wooyun.org%s \n' % (tag.string,''.join(tag['href']))).encode('utf-8')
                if tag.string.find('TV') > 0 :
                    # 匹配目标关键字
                    print 'bingo'
                    target.write(res)

                result.write(res)
                print '%s : %s  page : %s  --> next ' % (codeStrEnd,codeStr,page)
        target.close()
        result.close()
        page = page + 1
        if page > PAGE_MAX :
            # 读取超过PAGE_MAX页强制终止
            print '  --> loop end '
            breakTag = 1
        time.sleep(1)

    code = open(CODE_FILENAME,'w')
    code.write(codeStrEnd)
    code.close()


if __name__ == '__main__':
    doGet()
