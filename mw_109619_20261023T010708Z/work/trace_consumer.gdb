set pagination off
set confirm off
handle SIGSEGV stop print
handle SIGABRT stop print
handle SIGBUS stop print

break php_url_encode
commands
  silent
  printf "URLENCODE s=%p len=%lu\n", $rdi, $rsi
  bt 5
  continue
end

break php_session_reset_id
commands
  silent
  set $ps = (char *)&ps_globals
  set $id = *(unsigned long *)($ps + 0x10)
  printf "RESET_ID ps=%p id=%p", $ps, $id
  if $id
    printf " refcnt=%u len=%lu\n", *(unsigned int *)$id, *(unsigned long *)($id + 0x10)
    x/40bx $id
  else
    printf "\n"
  end
  continue
end

continue
echo \n=== STOPPED ===\n
bt 30
info registers rip rdi rsi rdx
