<?php
header('Content-Type: text/plain');
error_log("PRODUCER_OK_START pid=".getmypid());
$r = unserialize('a:2:{i:0;i:1;i:1;s:3:"abc";}');
echo "OK PID=".getmypid()." n=".count($r)."\n";
