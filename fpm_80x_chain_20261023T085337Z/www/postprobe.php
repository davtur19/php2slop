<?php
header('Content-Type: text/plain');
echo "PID=".getmypid()." post=".(isset($_POST)?count($_POST):-1)." files=".(isset($_FILES)?count($_FILES):-1);
echo " cl=".(isset($_SERVER['CONTENT_LENGTH'])?$_SERVER['CONTENT_LENGTH']:'NULL');
echo " te=".(isset($_SERVER['HTTP_TRANSFER_ENCODING'])?$_SERVER['HTTP_TRANSFER_ENCODING']:'NULL')."\n";
