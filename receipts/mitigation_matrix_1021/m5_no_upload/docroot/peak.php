<?php
session_start();
header('Content-Type: text/plain');
echo "peak_real=", memory_get_peak_usage(true), "\n";
echo "peak_emalloc=", memory_get_peak_usage(false), "\n";
echo "files=", count($_FILES), "\n";
echo "post_keys=", implode(',', array_keys($_POST)), "\n";
echo "pid=", getmypid(), "\n";
