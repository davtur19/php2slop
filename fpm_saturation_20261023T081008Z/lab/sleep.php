<?php
$s = isset($_GET['s']) ? (float)$_GET['s'] : 10.0;
usleep((int)($s * 1000000));
echo "slept=", $s, " pid=", getmypid(), "\n";
