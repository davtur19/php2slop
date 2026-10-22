<?php
session_start();
$foo = $_SESSION['foo'] ?? 'none';
echo "PID=", getmypid(), " SID=", session_id(), " FOO=", $foo, "\n";
