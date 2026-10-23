<?php
header('Content-Type: text/plain');
error_log("PRODUCER_SER_START pid=".getmypid());
$n = isset($_GET['n']) ? (int)$_GET['n'] : 300000;
$chunk = str_repeat('A', 512);
$arr = array_fill(0, $n, $chunk);
error_log("PRODUCER_SER_PRE pid=".getmypid()." n=".$n." mem=".memory_get_usage(true));
$s = serialize($arr);
error_log("PRODUCER_SER_AFTER pid=".getmypid()." len=".strlen($s));
echo "NO_BAILOUT len=".strlen($s)."\n";
