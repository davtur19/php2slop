<?php
// Arm target: normal session-using script. The multipart OOM happens during
// request startup, before this code runs (pre-RINIT fatal).
// no session_start
header('Content-Type: text/plain');
$upgName = ini_get('session.upload_progress.name');
$upgKey = ini_get('session.upload_progress.prefix') . $upgName;
echo "S:count=" . (isset($_SESSION['count']) ? (int)$_SESSION['count'] : 0) . "\n";
echo "sid=" . session_id() . "\n";
echo "post_keys=" . implode(',', array_keys($_POST)) . "\n";
echo "files_keys=" . implode(',', array_keys($_FILES)) . "\n";
if (!empty($_FILES)) {
    foreach ($_FILES as $k => $f) {
        if (is_array($f)) {
            echo "file[$k]: name_len=" . strlen((string)($f['name'] ?? ''))
               . " size=" . (string)($f['size'] ?? '')
               . " error=" . (string)($f['error'] ?? '') . "\n";
        }
    }
}
echo "session_upg=" . (isset($_SESSION[$upgKey]) ? 'yes' : 'no') . "\n";
echo "mem_limit=" . ini_get('memory_limit') . "\n";
echo "post_max=" . ini_get('post_max_size') . "\n";
echo "file_uploads=" . var_export(ini_get('file_uploads'), true) . "\n";
echo "enable_post_data_reading=" . var_export(ini_get('enable_post_data_reading'), true) . "\n";
echo "max_file_uploads=" . ini_get('max_file_uploads') . "\n";
echo "upg_enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "upg_name=" . $upgName . "\n";
echo "save_path=" . session_save_path() . "\n";
echo "pid=" . getmypid() . "\n";
