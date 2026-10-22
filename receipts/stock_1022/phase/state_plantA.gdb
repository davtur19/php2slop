set pagination off
set confirm off
set $lvl = basic_globals.unserialize.level
set $d = basic_globals.unserialize.data
printf "BG level=%ld data=%p\n", $lvl, $d
if $d
  printf "last=%p first_dtor=%p last_dtor=%p cur=%ld max=%ld entries.used=%ld entries.next=%p\n", $d->last, $d->first_dtor, $d->last_dtor, $d->cur_depth, $d->max_depth, $d->entries.used_slots, $d->entries.next
  x/12gx $d
  if $d->first_dtor
    printf "dtor used=%ld next=%p\n", $d->first_dtor->used_slots, $d->first_dtor->next
    x/4gx $d->first_dtor
  end
end
detach
quit
