<?php
header('Content-Type: text/plain');
$n = isset($_GET['n']) ? (int)$_GET['n'] : 300000;
$arr = array_fill(0, $n, str_repeat('A', 512));
$s = serialize($arr);
echo "NO_BAILOUT ".strlen($s)."\n";
