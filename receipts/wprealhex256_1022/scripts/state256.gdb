set pagination off
set confirm off
set auto-load safe-path /
symbol-file /tmp/opencode/realapps/install_realapps_np/sbin/php-fpm
set $lvl = basic_globals.unserialize.level
set $d = basic_globals.unserialize.data
printf "BG level=%ld data=%p\n", $lvl, $d
if $d
  printf "last=%p first_dtor=%p last_dtor=%p cur=%ld max=%ld entries.used=%ld entries.next=%p\n", $d->last, $d->first_dtor, $d->last_dtor, $d->cur_depth, $d->max_depth, $d->entries.used_slots, $d->entries.next
  x/9gx $d
  if $d->first_dtor
    printf "dtor used=%ld next=%p\n", $d->first_dtor->used_slots, $d->first_dtor->next
    x/4gx $d->first_dtor
  end
end
printf "pser=%p ser1decode=%p ser1encode=%p\n", *(void**)0x22d0f20, *(void**)0x22c54c8, *(void**)0x22c54c0
printf "alloc real_size=%lu chunks=%u cached=%u\n", alloc_globals.mm_heap->real_size, alloc_globals.mm_heap->chunks_count, alloc_globals.mm_heap->cached_chunks_number
detach
quit
