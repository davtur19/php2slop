#!/usr/bin/env python3
import http.client, re, random, string, os, time, json
HOST='127.0.0.1'; PORT=28891
SESS='/tmp/opencode/research/wprealhex_20261022T011837Z/sessions'
sid='umreg'
def req(method,path,body=None,headers=None,timeout=180):
    c=http.client.HTTPConnection(HOST,PORT,timeout=timeout)
    c.request(method,path,body=body,headers=headers or {})
    r=c.getresponse(); d=r.read(); h=dict(r.getheaders()); c.close()
    return r.status,h,d
st,h,body=req('GET','/um-register/',headers={'Cookie':'PHPSESSID='+sid})
html=body.decode('utf-8','replace')
nonce=re.search(r'name="_wpnonce"\s+value="([^"]+)"',html)
fid=re.search(r'name="form_id"[^>]*value="([^"]+)"',html)
print('GET status',st,'nonce',nonce.group(1) if nonce else None,'form_id',fid.group(1) if fid else None,'len',len(body))
sf=os.path.join(SESS,'sess_'+sid)
print('session after GET',os.path.getsize(sf) if os.path.exists(sf) else None)
marker='UMMARK_'+''.join(random.choice(string.ascii_lowercase) for _ in range(8))
big='FIRST_'+marker+'_'+('Q'*3000000)
fields=[('form_id',fid.group(1) if fid else '30'),('_wpnonce',nonce.group(1) if nonce else ''),
        ('_wp_http_referer','/um-register/'),('user_login','umtest'+marker[-6:]),
        ('user_email','umtest%s@example.com'%marker[-6:]),('user_password','Zz!9'+marker[-6:]+'pass'),
        ('confirm_user_password','Zz!9'+marker[-6:]+'pass'),('first_name-30',big),
        ('last_name-30','LAST_'+marker)]
from urllib.parse import urlencode
body=urlencode(fields).encode()
print('POST bytes',len(body))
t0=time.time(); st,h,d=req('POST','/um-register/',body=body,headers={'Cookie':'PHPSESSID='+sid,'Content-Type':'application/x-www-form-urlencoded','Referer':'http://127.0.0.1:28891/um-register/'},timeout=300)
print('POST status',st,'elapsed %.2f'%(time.time()-t0),'resp len',len(d),'loc',h.get('Location'))
open('/tmp/opencode/umreg_post_resp.html','wb').write(d)
time.sleep(0.5)
if os.path.exists(sf):
    data=open(sf,'rb').read()
    print('session size',len(data),'has marker',marker.encode() in data)
    print('session head',data[:200])
else:
    print('session file missing')
# check DB for the marker via WP bootstrap
out=os.popen("php -r '$m=\"%s\"; require \"/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php\"; global $wpdb; $r=$wpdb->get_var($wpdb->prepare(\"SELECT COUNT(*) FROM {$wpdb->users} WHERE user_login LIKE %s\", \"umtest%%\")); echo \"users=\".$r.\"\\n\"; $t=$wpdb->get_var($wpdb->prepare(\"SELECT option_value FROM {$wpdb->options} WHERE option_name LIKE %s AND option_value LIKE %s LIMIT 1\", \"%%transient%%\", \"%%\".$m.\"%%\")); echo \"transient_hit=\".($t?strlen($t):0).\"\\n\";'" % marker)
print(out)
