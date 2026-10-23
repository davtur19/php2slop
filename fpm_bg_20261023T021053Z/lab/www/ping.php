<?php
header('Content-Type: text/plain');
echo "PING PID=".getmypid()." STATUS=".session_status()."\n";
