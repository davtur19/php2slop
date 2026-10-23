<?php
header('Content-Type: text/plain');
ini_set('max_execution_time', '2');
function bg_cb($name) {
    error_log("BG_CB_ENTER pid=".getmypid()." name=".$name." t=".microtime(true));
    $end = microtime(true) + 10;
    $x = 0;
    while (microtime(true) < $end) { $x += strlen(str_repeat('a', 1000)); }
    error_log("BG_CB_EXIT pid=".getmypid()." x=".$x);
    return 'stdClass';
}
ini_set('unserialize_callback_func', 'bg_cb');
$n = isset($_GET['n']) ? (int)$_GET['n'] : 5;
$s = 'a:'.$n.':{';
for ($i = 0; $i < $n; $i++) { $s .= 'i:'.$i.';O:3:"Nop":0:{}'; }
$s .= '}';
error_log("PRODUCER_TIMEOUT_START pid=".getmypid()." n=".$n." len=".strlen($s));
$r = unserialize($s);
error_log("PRODUCER_TIMEOUT_AFTER pid=".getmypid());
echo "NO_BAILOUT\n";
