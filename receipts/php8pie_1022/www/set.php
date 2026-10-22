<?php
session_start();
if (isset($_POST['x'])) { $_SESSION['x'] = $_POST['x']; }
echo "PID=", getmypid(), " len=", strlen($_SESSION['x'] ?? ''), "\n";
