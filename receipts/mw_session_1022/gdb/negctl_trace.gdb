set pagination off
set confirm off
break zif_passthru
commands
  silent
  echo \n=== ZIF_PASSTHRU NEGCTL ===\n
  printf "rdi(execute_data)=%p rsi(return_value)=%p\n", $rdi, $rsi
  x/12bx $rdi
  bt 5
  detach
  quit
end
continue
