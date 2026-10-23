<?php
header('Content-Type: text/plain');
echo "CONSUMER PID=".getmypid()." STATUS=".session_status()." SID=".session_id();
echo " SESSION=".(isset($_SESSION) ? json_encode(array_keys($_SESSION)) : 'unset')."\n";
