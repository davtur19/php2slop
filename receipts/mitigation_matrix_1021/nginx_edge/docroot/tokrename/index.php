<?php
// lane probe / arm target.  session_start() is here because the stock arm
// targets a normal session-using script; the OOM happens BEFORE this code runs.
session_start();
header('Content-Type: text/plain');
echo "S:count=" . (isset($_SESSION['count']) ? (int)$_SESSION['count'] : 0) . "\n";
echo "sid=" . session_id() . "\n";
echo "post_keys=" . implode(',', array_keys($_POST)) . "\n";
echo "files_keys=" . implode(',', array_keys($_FILES)) . "\n";
echo "mem_limit=" . ini_get('memory_limit') . "\n";
echo "post_max=" . ini_get('post_max_size') . "\n";
echo "upg_enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "upg_name=" . ini_get('session.upload_progress.name') . "\n";
echo "save_path=" . session_save_path() . "\n";
