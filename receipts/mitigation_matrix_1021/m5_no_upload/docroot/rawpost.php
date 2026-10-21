<?php
header('Content-Type: text/plain');
$raw = @file_get_contents('php://input');
echo "raw:len=", ($raw === false ? 'false' : strlen($raw)), "\n";
echo "raw:post_keys=", implode(',', array_keys($_POST)), "\n";
echo "raw:files=", count($_FILES), "\n";
echo "raw:pid=", getmypid(), "\n";
