<?php
header('Content-Type: text/plain');
echo "fold:file_uploads=", var_export(ini_get('file_uploads'), true), "\n";
echo "fold:memory_limit=", ini_get('memory_limit'), "\n";
echo "fold:pid=", getmypid(), "\n";
