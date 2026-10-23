<?php
header('Content-Type: text/plain');
session_start();
$_SESSION['p'] = isset($_GET['v']) ? $_GET['v'] : 'hello';
session_write_close();
echo "SET PID=".getmypid()."\n";
