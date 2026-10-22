set pagination off
set confirm off
set $lvl = basic_globals.unserialize.level
set $d = basic_globals.unserialize.data
printf "BG_LEVEL=%ld\n", $lvl
printf "BG_DATA=%p\n", $d
if $d
  printf "P_LAST=%p\n", $d->last
  printf "P_FIRST_DTOR=%p\n", $d->first_dtor
  printf "P_LAST_DTOR=%p\n", $d->last_dtor
  printf "CUR=%ld\n", $d->cur_depth
  printf "MAX=%ld\n", $d->max_depth
  printf "ENTRIES_USED=%ld\n", $d->entries.used_slots
  x/8gx $d
  if $d->last_dtor
    printf "DTOR_USED=%ld\n", $d->last_dtor->used_slots
    printf "DTOR_NEXT=%p\n", $d->last_dtor->next
    x/4gx $d->last_dtor
  end
end
detach
quit
