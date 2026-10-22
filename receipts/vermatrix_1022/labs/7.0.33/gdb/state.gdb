set pagination off
set confirm off
set $lvl = basic_globals.unserialize.level
set $d = basic_globals.unserialize.data
printf "BG_LEVEL=%ld\n", $lvl
printf "BG_DATA=%p\n", $d
if $d
  printf "P_FIRST=%p\n", $d->first
  printf "P_LAST=%p\n", $d->last
  printf "P_FIRST_DTOR=%p\n", $d->first_dtor
  printf "P_LAST_DTOR=%p\n", $d->last_dtor
  x/4gx $d
  if $d->last_dtor
    printf "DTOR_USED=%ld\n", ((var_dtor_entries*)$d->last_dtor)->used_slots
    printf "DTOR_NEXT=%p\n", ((var_dtor_entries*)$d->last_dtor)->next
    x/4gx ((var_dtor_entries*)$d->last_dtor)
  end
end
detach
quit
