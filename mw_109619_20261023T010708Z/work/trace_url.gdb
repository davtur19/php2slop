set pagination off
set confirm off
break php_url_encode
commands
  silent
  printf "URLENCODE s=%p len=%lu\n", $rdi, $rsi
  bt 6
  continue
end
continue
echo \n=== SCRIPT END ===\n
