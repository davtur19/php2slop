set pagination off
set logging file /tmp/opencode/realapps/side/p4_trace_2.log
set logging enabled on
set env REQUEST_METHOD=POST
set env CONTENT_TYPE=multipart/form-data; boundary=BOUND
set env CONTENT_LENGTH=123403
set env SCRIPT_FILENAME=/tmp/opencode/realapps/side/empty.php
set env HTTP_COOKIE=PHPSESSID=mach-trace-001
break session.c:3256
commands
  silent
  printf "E1_CAPTURE_POST data_arr=%p ref=%d bucket=%p\n", (void*)progress->data.value.arr, Z_REFCOUNT(progress->data), (void*)progress->post_bytes_processed
  continue
end
break session.c:3282
commands
  silent
  printf "E2_CAPTURE_CURF curf=%p ref=%d bucket=%p\n", (void*)progress->current_file.value.arr, Z_REFCOUNT(progress->current_file), (void*)progress->current_file_bytes_processed
  continue
end
break session.c:3295
commands
  silent
  printf "E3_DATA_WRITE curf_bucket=%p post_bucket=%p\n", (void*)progress->current_file_bytes_processed, (void*)progress->post_bytes_processed
  continue
end
break session.c:3315
commands
  silent
  printf "E4_FEOF_WRITE post_bucket=%p\n", (void*)progress->post_bytes_processed
  continue
end
break session.c:3328
commands
  silent
  printf "E5_END_SEPARATE data_arr=%p ref=%d post_bucket=%p\n", (void*)progress->data.value.arr, Z_REFCOUNT(progress->data), (void*)progress->post_bytes_processed
  continue
end
break session.c:3339
commands
  silent
  printf "E6_END_SHUTDOWN data_arr=%p\n", (void*)progress->data.value.arr
  continue
end
run < /tmp/opencode/realapps/side/body_3f.bin > /tmp/opencode/realapps/side/out.txt
