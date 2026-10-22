set pagination off
set confirm off
break zif_passthru
commands
  silent
  echo \n=== ZIF_PASSTHRU ===\n
  printf "rdi=%p rsi=%p rdx=%p\n", $rdi, $rsi, $rdx
  bt 6
  printf "num_args word @rdi+0x2c: "
  x/1xw $rdi+0x2c
  printf "func @rdi+0x18: "
  x/1gx $rdi+0x18
  x/8bx $rdi
  continue
end
continue
