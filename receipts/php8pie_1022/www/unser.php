<?php
$mode = $_POST['mode'] ?? 'user_error';
$p    = $_POST['p'] ?? 'x';
$pad  = (int)($_POST['pad'] ?? 0);
ini_set('memory_limit', '2M');
if ($pad > 0) { $GLOBALS['padbuf'] = str_repeat('P', $pad); }
if ($mode === 'user_error') {
    set_error_handler(function ($no, $str) { trigger_error('stop', E_USER_ERROR); }, E_ALL);
}
echo "PID=", getmypid(), " MODE=", $mode, " PAD=", $pad, " PLEN=", strlen($p), "\n";
$r = unserialize($p);
echo "AFTER type=", gettype($r), "\n";
