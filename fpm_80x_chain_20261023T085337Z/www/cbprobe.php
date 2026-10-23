<?php header('Content-Type: text/plain');
echo "STATUS=".session_status()." ID=".session_id()." POST=".count($_POST)." FILES=".count($_FILES)." KEYS=".json_encode(array_slice(array_keys($_POST),0,5))."\n";
