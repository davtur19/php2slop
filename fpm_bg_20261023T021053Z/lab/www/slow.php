<?php
header('Content-Type: text/plain');
error_log("SLOW_START pid=".getmypid());
$s = isset($_GET['s']) ? (int)$_GET['s'] : 15;
sleep($s);
error_log("SLOW_END pid=".getmypid());
echo "SLOW_DONE PID=".getmypid()."\n";
