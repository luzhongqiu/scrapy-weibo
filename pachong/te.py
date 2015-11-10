# -*- coding: utf-8 -*-
__author__ = 'luzho_000'

import re
with open('parse_item4.txt','r') as f:
    data=f.read()
    uid=re.findall(r"uid']='(.*?)'",data)[0]
    print uid
