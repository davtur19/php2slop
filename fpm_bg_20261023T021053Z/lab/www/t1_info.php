<?php
header('Content-Type: text/plain');
echo "PID=".getmypid()
    ." save_path=".ini_get('session.save_path')
    ." errlog=".ini_get('error_log')
    ." mem=".ini_get('memory_limit')
    ." version=".PHP_VERSION."\n";
