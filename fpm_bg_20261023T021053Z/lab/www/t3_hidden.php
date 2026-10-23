<?php
header('Content-Type: text/plain');
echo "T3_HIDDEN pid=".getmypid()
    ." method=".($_SERVER['REQUEST_METHOD'] ?? '?')
    ." uri=".($_SERVER['REQUEST_URI'] ?? '?')
    ." qs=".($_SERVER['QUERY_STRING'] ?? '?')
    ." script=".($_SERVER['SCRIPT_FILENAME'] ?? '?')
    ."\n";
