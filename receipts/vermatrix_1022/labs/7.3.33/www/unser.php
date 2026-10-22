<?php
$mode = $_POST['mode'] ?? 'user_error';
$p    = $_POST['p'] ?? 'x';
$pad  = (int)($_POST['pad'] ?? 0);
ini_set('memory_limit', $_POST['mem'] ?? '2M');
if ($pad > 0) {
    $GLOBALS['padbuf'] = str_repeat('P', $pad);
}
$shape = (int)($_POST['shape'] ?? 0);
if ($shape > 0) {
    $GLOBALS['shapebuf'] = [];
    for ($i = 0; $i < $shape; $i++) {
        $GLOBALS['shapebuf'][] = str_repeat('S', 8);
    }
}
if ($mode === 'user_error') {
    set_error_handler(function ($no, $str) { trigger_error('stop', E_USER_ERROR); }, E_ALL);
}
echo "PID=", getmypid(), " MODE=", $mode, " PAD=", $pad, " PLEN=", strlen($p), "\n";
$kfree = (int)($_POST['kfree'] ?? 0);
for ($i = 0; $i < $kfree; $i++) {
    if ($shape > 0) {
        array_pop($GLOBALS['shapebuf']);
    } else {
        $tmpfree = str_repeat('T', 8);
        unset($tmpfree);
    }
}
$r = unserialize($p);
echo "AFTER type=", gettype($r), "\n";
