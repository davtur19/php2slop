set confirm off
set pagination off
set logging file /tmp/opencode/realapps/side/p4_trace_3.log
set logging enabled on

break session.c:3155
commands
  silent
  printf "U3155 sess=%p sess_rc=%d datatbl=%p data_rc=%d\n", sess_var->value.arr, sess_var->value.arr->gc.refcount, progress->data.value.arr, progress->data.value.arr->gc.refcount
  continue
end

break session.c:3256
commands
  silent
  printf "A3256 datatbl=%p data_rc=%d postp=%p arData=%p\n", progress->data.value.arr, progress->data.value.arr->gc.refcount, progress->post_bytes_processed, progress->data.value.arr->arData
  continue
end

break session.c:3268
commands
  silent
  if progress->current_file.value.arr != 0
    printf "H3268 PRIOR_curf=%p prior_rc=%d\n", progress->current_file.value.arr, progress->current_file.value.arr->gc.refcount
  else
    printf "H3268 curf=UNDEF\n"
  end
  continue
end

break session.c:3282
commands
  silent
  printf "B3282 curftbl=%p curf_rc=%d curfbp=%p curf_arData=%p\n", progress->current_file.value.arr, progress->current_file.value.arr->gc.refcount, progress->current_file_bytes_processed, progress->current_file.value.arr->arData
  continue
end

break session.c:3295
commands
  silent
  printf "C3295 curfbp=%p curftbl=%p curf_arData=%p off=%ld len=%ld\n", progress->current_file_bytes_processed, progress->current_file.value.arr, progress->current_file.value.arr->arData, (long)data->offset, (long)data->length
  continue
end

break session.c:3296
commands
  silent
  printf "D3296 postp=%p datatbl=%p data_arData=%p data_rc=%d\n", progress->post_bytes_processed, progress->data.value.arr, progress->data.value.arr->arData, progress->data.value.arr->gc.refcount
  continue
end

break session.c:3315
commands
  silent
  printf "E3315 postp=%p datatbl=%p data_arData=%p data_rc=%d\n", progress->post_bytes_processed, progress->data.value.arr, progress->data.value.arr->arData, progress->data.value.arr->gc.refcount
  continue
end

break session.c:3328
commands
  silent
  printf "F3328 datatbl=%p data_rc=%d arData=%p postp=%p\n", progress->data.value.arr, progress->data.value.arr->gc.refcount, progress->data.value.arr->arData, progress->post_bytes_processed
  continue
end

break session.c:3330
commands
  silent
  printf "G3330 postp=%p val=%ld datatbl=%p data_arData=%p data_rc=%d\n", progress->post_bytes_processed, (long)data->post_bytes_processed, progress->data.value.arr, progress->data.value.arr->arData, progress->data.value.arr->gc.refcount
  continue
end

break session.c:3340
commands
  silent
  printf "X3340 postEND datatbl_ptr_field=%p\n", progress->data.value.arr
  continue
end

run < /tmp/opencode/realapps/side/body_3f.bin > /tmp/opencode/realapps/side/gdb_out.txt
