<?php
session_start();
$_SESSION['n'] = ($_SESSION['n'] ?? 0) + 1;
usleep((int)((isset($_GET['s']) ? (float)$_GET['s'] : 2.0) * 1000000));
echo "pid=", getmypid(), " sid=", session_id(), " n=", $_SESSION['n'], "\n";
