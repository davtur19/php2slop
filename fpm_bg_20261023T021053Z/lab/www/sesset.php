<?php
header('Content-Type: text/plain');
if (isset($_GET['id']) && $_GET['id'] !== '') { session_id($_GET['id']); }
session_start();
$_SESSION['p'] = isset($_GET['v']) ? $_GET['v'] : 'i:1;';
$id = session_id();
session_write_close();
echo "SESSET PID=".getmypid()." SID=".$id." FILE=".session_save_path()."/sess_".$id."\n";
