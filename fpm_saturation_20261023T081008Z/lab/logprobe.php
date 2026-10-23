<?php
$t0 = microtime(true);
$line = sprintf("t=%.6f pid=%d method=%s cl=%s te=%s post=%d files=%d\n",
    $t0, getmypid(), $_SERVER['REQUEST_METHOD'] ?? '?',
    var_export($_SERVER['CONTENT_LENGTH'] ?? null, true),
    var_export($_SERVER['HTTP_TRANSFER_ENCODING'] ?? null, true),
    count($_POST), count($_FILES));
file_put_contents('/tmp/reqlog.txt', $line, FILE_APPEND | LOCK_EX);
echo "pid=", getmypid(), " logged\n";
