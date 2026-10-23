<?php
header('Content-Type: text/plain');
error_log("PRODUCER_OOM_START pid=".getmypid());
$n = isset($_GET['n']) ? (int)$_GET['n'] : 8000000;
$s = 'a:'.$n.':{' . str_repeat('i:1;', $n) . '}';
error_log("PRODUCER_OOM_PAYLOAD pid=".getmypid()." n=".$n." len=".strlen($s)." mem=".memory_get_usage(true));
$r = unserialize($s);
error_log("PRODUCER_OOM_AFTER pid=".getmypid()." count=".(is_array($r)?count($r):-1));
echo "NO_BAILOUT\n";
