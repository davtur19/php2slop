for u in "$@"; do
  code=$(curl -sL --max-time 35 -o /tmp/chk.html -w "%{http_code}" -A "Mozilla/5.0" "$u")
  t=$(python3 -c "
import re,html
s=open('/tmp/chk.html',encoding='utf-8',errors='ignore').read()
m=re.search(r'<title[^>]*>(.*?)</title>',s,re.S|re.I)
print(html.unescape(re.sub(r'\s+',' ',m.group(1))).strip()[:90] if m else '')
")
  echo "$code | $u | $t"
done
