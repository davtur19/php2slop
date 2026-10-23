<?php
header('Content-Type: text/plain');
$old = ini_set('unserialize_callback_func', 'bg_cb');
echo "old=".var_export($old,true)." now=".var_export(ini_get('unserialize_callback_func'),true)."\n";
$tests = ['a:1:{O:8:"stdClass":0:{}}', 'a:1:{O:3:"Nop":0:{}}', 'O:8:"stdClass":0:{}'];
foreach ($tests as $s) {
  $r = @unserialize($s);
  echo "in=".$s." => ".gettype($r)." err=".json_encode(error_get_last()['message'] ?? null)."\n";
}
