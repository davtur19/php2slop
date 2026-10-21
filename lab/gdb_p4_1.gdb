set pagination off
set logging file /tmp/opencode/realapps/side/p4_trace_1.log
set logging enabled on
break session.c:3256
commands
  silent
  printf "E1_CAPTURE_POST data_arr=%p ref=%d bucket=%p\n", (void*)progress->data.value.arr, Z_REFCOUNT(progress->data), (void*)progress->post_bytes_processed.value.loopv
end
break session.c:3282
commands
  silent
  printf "E2_CAPTURE_CURF curf=%p ref=%d bucket=%p\n", (void*)progress->current_file.value.arr, Z_REFCOUNT(progress->current_file), (void*)progress->current_file_bytes_processed.value.loopv2
end
break session.c:3295
commands
  silent
  printf "E3_DATA_WRITE curf_bucket=%p\n", (void*)progress->current_file_bytes_processed
end
break session.c:3315
commands
  silent
  printf "E4_FEOF_WRITE post_bucket=%p\n", (void*)progress->post_bytes_processed
end
break session.c:3328
commands
  silent
  printf "E5_END_SEPARATE data_arr=%p ref=%d\n", (void*)progress->data.value.arr, Z_REFCOUNT(progress->data)
end
continue
