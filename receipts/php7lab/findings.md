###### RUN A: USE_ZEND_ALLOC=1 (default, OOM active)
R1:  len= 0 oom= False b''
R2:  len= 0 oom= False b''
R3:  len= 0 oom= False b''

###### RUN B: USE_ZEND_ALLOC=0 (malloc, limit likely inert)
R1: HTTP/1.1 200 OK len= 173 oom= False b' Oct 2026 13:12:14 GMT\r\nConnection: close\r\nX-Powered-By: PHP/7.4.33\r\nContent-typ'
R2: HTTP/1.1 200 OK len= 173 oom= False b' Oct 2026 13:12:14 GMT\r\nConnection: close\r\nX-Powered-By: PHP/7.4.33\r\nContent-typ'
R3: HTTP/1.1 200 OK len= 173 oom= False b' Oct 2026 13:12:15 GMT\r\nConnection: close\r\nX-Powered-By: PHP/7.4.33\r\nContent-typ'

###### ASAN hits:
none
###### parity:
1139:PHPAPI php_serialize_data_t php_var_serialize_init() {
1141:	/* fprintf(stderr, "SERIALIZE_INIT      == lock: %u, level: %u\n", BG(serialize_lock), BG(serialize).level); */
1142:	if (BG(serialize_lock) || !BG(serialize).level) {
1148:			BG(serialize).level = 1;
1152:		++BG(serialize).level;
1158:	/* fprintf(stderr, "SERIALIZE_DESTROY   == lock: %u, level: %u\n", BG(serialize_lock), BG(serialize).level); */
3151:		Z_TRY_ADDREF(progress->data);
LABCOMPLETE

###### BISECT (fresh server per case):
[fl128-mem8M]  R1-R3: silent close len=0, no fatal, no ASAN; post=EMPTY (dispatcher wedged)
[fl262144-mem64M] R1-R3: 200 OK len=173 (normal index response); post=200, arm shape is VALID, request survives when no OOM
[fl262144-mem8M] R1-R3: silent close len=0; post=EMPTY
[fl32768-mem8M] R1-R3: silent close len=0; post=EMPTY
⇒ php7.4.33 built-in server: machinery OOM pre-RINIT = silent close + WEDGE (no crash, no asan), different from 8.5.10 (R1 fatal body, R2 diverged len, R3 SEGV)
⇒ OOM trigger is the arm BODY machinery traffic (20×262144 chunks), not filename length
