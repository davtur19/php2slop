import sys
total=int(sys.argv[1]); out=sys.argv[2]
sm=b'S'*32
head=b'S|s:32:"'+sm+b'";J|i:4096;'
L=total-len(head)-len(b'K|s:"')-2-1
for _ in range(20):
    hdr=b'K|s:%d:"'%L; want=total-len(head)-len(hdr)-2
    if want==L: break
    L=want
hdr=b'K|s:%d:"'%L
rec=head+hdr+b'A'*L+b'";'
assert len(rec)==total,(len(rec),total)
open(out,'wb').write(rec)
