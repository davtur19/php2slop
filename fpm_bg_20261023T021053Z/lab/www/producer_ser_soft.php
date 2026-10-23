<?php
header('Content-Type: text/plain');
error_log("PRODUCER_SER_SOFT_START pid=".getmypid());
$mb = isset($_GET['mb']) ? (int)$_GET['mb'] : 120;
$n = isset($_GET['n']) ? (int)$_GET['n'] : 30000;
$ballast = str_repeat('B', $mb * 1024 * 1024);
$arr = array_fill(0, $n, str_repeat('C', 512));
error_log("PRODUCER_SER_SOFT_PRE pid=".getmypid()." mb=".$mb." n=".$n." mem=".memory_get_usage(true));
$s = serialize($arr);
error_log("PRODUCER_SER_SOFT_AFTER pid=".getmypid()." len=".strlen($s));
echo "NO_BAILOUT len=".strlen($s)."\n";
