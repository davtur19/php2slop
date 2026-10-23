<?php
header('Content-Type: text/plain');
echo "T3_TARGET pid=".getmypid()
    ." method=".($_SERVER['REQUEST_METHOD'] ?? '?')
    ." uri=".($_SERVER['REQUEST_URI'] ?? '?')
    ." ct=".($_SERVER['CONTENT_TYPE'] ?? '?')
    ." clen=".($_SERVER['CONTENT_LENGTH'] ?? '?')
    ." post=".(isset($_POST) ? json_encode(array_keys($_POST)) : 'unset')
    ."\n";
