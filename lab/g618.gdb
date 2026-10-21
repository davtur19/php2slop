set pagination off
set confirm off
set logging file /tmp/opencode/realapps/side/p618_trace.log
set logging overwrite on
set logging enabled on
set $armed_inner = 0
set $post_ptr = 0
set $inner_ptr = 0
set $data_ht = 0
set $cur_ht = 0
# outer: cache assigned at 3256; stop after it (3258)
break session.c:3258
commands
 silent
 set $data_ht = progress->data.value.arr
 set $post_ptr = progress->post_bytes_processed
 printf "EVT ARM-OUTER ht=%p post_ptr=%p\n", $data_ht, $post_ptr
 watch -l progress->post_bytes_processed->value.lval
 commands
  silent
  printf "WATCH OUTER-BUCKET ptr=%p val=%ld\n", $post_ptr, *(long*)($post_ptr)
  bt 5
  continue
 end
 watch -l progress->data.value.arr->gc.refcount
 commands
  silent
  printf "WATCH DATA-RC ht=%p rc=%u ti=%x\n", $data_ht, *(unsigned int*)($data_ht), *((unsigned int*)($data_ht) + 1)
  bt 5
  continue
 end
 continue
end
# inner: cache assigned at 3282; its first write is 3284 -> stop there
break session.c:3284
commands
 silent
 if $armed_inner == 0
  set $armed_inner = 1
  set $cur_ht = progress->current_file.value.arr
  set $inner_ptr = progress->current_file_bytes_processed
  printf "EVT ARM-INNER curht=%p inner_ptr=%p\n", $cur_ht, $inner_ptr
  watch -l progress->current_file_bytes_processed->value.lval
  commands
   silent
   printf "WATCH INNER-BUCKET ptr=%p val=%ld\n", $inner_ptr, *(long*)($inner_ptr)
   bt 5
   continue
  end
  watch -l progress->current_file.value.arr->gc.refcount
  commands
   silent
   printf "WATCH CURFILE-RC ht=%p rc=%u ti=%x\n", $cur_ht, *(unsigned int*)($cur_ht), *((unsigned int*)($cur_ht) + 1)
   bt 5
   continue
  end
 end
 printf "EVT INNER-REFRESH curht=%p inner_ptr=%p armed=%d\n", progress->current_file.value.arr, progress->current_file_bytes_processed, $armed_inner
 continue
end
break session.c:3338
commands
 silent
 printf "EVT END-DTOR data=%p rc=%u curht=%p currc=%u\n", progress->data.value.arr, *(unsigned int*)(progress->data.value.arr), progress->current_file.value.arr, *(unsigned int*)(progress->current_file.value.arr)
 continue
end
run < /tmp/opencode/realapps/side/tmp/f618.fifo
