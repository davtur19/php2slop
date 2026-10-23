set pagination off
set confirm off
set $stale = basic_globals.unserialize.data
printf "STALE=%p level=%u lock=%u\n", $stale, basic_globals.unserialize.level, basic_globals.serialize_lock
x/8gx $stale
set $hits = 0
watch *(long*)($stale+16)
commands
  set $hits = $hits + 1
  printf "WATCH_HIT %d\n", $hits
  bt 12
  printf "MEM:\n"
  x/8gx $stale
  if $hits >= 8
    detach
    quit
  end
  continue
end
continue
printf "STOPPED\n"
bt 15
printf "MEM:\n"
x/8gx $stale
detach
quit
