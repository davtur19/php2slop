set pagination off
set confirm off
break php_url_encode
commands
  silent
  printf "URLENCODE s=%p len=%lu\n", $rdi, $rsi
  if $rsi > 1024
    printf "HEADER at s-0x18:\n"
    x/6gx $rdi-0x18
    bt 8
  end
  continue
end
continue
echo \n=== SCRIPT END ===\n
