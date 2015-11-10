# -*- coding: utf-8 -*-
import scrapy,urllib,base64,re,json,rsa,binascii,hashlib
from scrapy.http import Request,FormRequest



class WeiboSpider(scrapy.Spider):
    name = "weibo"
    allowed_domains = ["weibo.com","sina.com.cn"]
    username="***********"
    pwd="*************"
    custom_settings = {
        'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0'
    }
    def start_requests(self):
        prelogin_url = 'http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=' + self.get_user(
        self.username) + '&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)';

        return [Request(url=prelogin_url,callback=self.parse_item1,method='GET')]

    def parse(self, response):
        pass

    def parse_item1(self, response):
        with open('parse_item1.txt','w') as f:
            f.write(response.body)
        json_data=re.findall('\((.*)\)',response.body)[0]
        data= eval(json_data)
        # print '==========================='
        # print data
        # print '==========================='
        servertime = str(data['servertime'])

        nonce = data['nonce']
        rsakv = data['rsakv']
        login_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'userticket': '1',
            'pagerefer': '',
            'vsnf': '1',
            'su': '',
            'service': 'miniblog',
            'servertime': '',
            'nonce': '',
            'pwencode': 'rsa2',
            'rsakv': '',
            'sp': '',
            'encoding': 'UTF-8',
            'prelt': '45',
            'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
            'returntype': 'META'
        }

        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        login_data['servertime'] = servertime
        login_data['nonce'] = nonce
        login_data['su'] = self.get_user(self.username)
        login_data['sp'] = self.get_pwd_rsa(self.pwd, servertime, nonce)
        login_data['rsakv'] = rsakv
        print '==========================='
        print login_data
        print '==========================='
        # login_data = urllib.urlencode(login_data)
        return [FormRequest(url=login_url,formdata=login_data,callback=self.parse_item2)]

    def parse_item2(self,response):
        with open('parse_item2.txt','w') as f:
            f.write(response.body)
        login_url = re.findall('location\.replace\(\'(.*?)\'\)',response.body)[0]
        print '==========================='
        print login_url
        print '==========================='

        return scrapy.Request(url=login_url,callback=self.parse_item3)

    def parse_item3(self,response):
        with open('parse_item3.txt','w') as f:
            f.write(response.body)
        patt_feedback = 'feedBackUrlCallBack\((.*)\)'
        p = re.compile(patt_feedback, re.MULTILINE)
        feedback = p.search(response.body).group(1)
        feedback_json = json.loads(feedback)
        if feedback_json['result']:
            self.logger.info(u'登录成功')
        else:
            self.logger.info(u'登录失败')

        return scrapy.Request(url='http://weibo.com/?wvr=5&lf=reg',callback=self.parse_item4)

    def parse_item4(self,response):
        with open('parse_item4.txt','w') as f:
            f.write(response.body)

        uid=re.findall(r"uid']='(.*?)'",response.body)[0]

        return scrapy.Request(url='http://weibo.com/%s/fans?rightmod=1&wvr=6'%uid,callback=self.parse_item5)

    def parse_item5(self,response):
        with open('parse_item5.txt','w') as f:
            f.write(response.body)

  # ==================================
    def get_user(self,username):
        username_ = urllib.quote(username)
        username = base64.encodestring(username_)[:-1]
        return username

    def get_pwd_rsa(self,pwd, servertime, nonce):
        """
            Get rsa2 encrypted password, using RSA module from https://pypi.python.org/pypi/rsa/3.1.1, documents can be accessed at
            http://stuvel.eu/files/python-rsa-doc/index.html
        """
        # n, n parameter of RSA public key, which is published by WEIBO.COM
        #hardcoded here but you can also find it from values return from prelogin status above
        weibo_rsa_n = 'EB2A38568661887FA180BDDB5CABD5F21C7BFD59C090CB2D245A87AC253062882729293E5506350508E7F9AA3BB77F4333231490F915F6D63C55FE2F08A49B353F444AD3993CACC02DB784ABBB8E42A9B1BBFFFB38BE18D78E87A0E41B9B8F73A928EE0CCEE1F6739884B9777E4FE9E88A1BBE495927AC4A799B3181D6442443'

        #e, exponent parameter of RSA public key, WEIBO uses 0x10001, which is 65537 in Decimal
        weibo_rsa_e = 65537
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(pwd)

        #construct WEIBO RSA Publickey using n and e above, note that n is a hex string
        key = rsa.PublicKey(int(weibo_rsa_n, 16), weibo_rsa_e)

        #get encrypted password
        encropy_pwd = rsa.encrypt(message, key)
        #trun back encrypted password binaries to hex string
        return binascii.b2a_hex(encropy_pwd)
