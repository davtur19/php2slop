<?php
header('Content-Type: text/plain');
session_start();
echo "SS PID=".getmypid()." STATUS=".session_status()." SID=".session_id()."\n";
