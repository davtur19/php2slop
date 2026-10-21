<?php
header('Content-Type: text/plain');
$k = 'file_uploads';
$m = 'max_file_uploads';
echo "dyn_file_uploads=", var_export(ini_get($k), true), "\n";
echo "lit_file_uploads=", var_export(ini_get('file_uploads'), true), "\n";
echo "dyn_max_file_uploads=", var_export(ini_get($m), true), "\n";
echo "lit_max_file_uploads=", var_export(ini_get('max_file_uploads'), true), "\n";
$e = 'enable_post_data_reading';
echo "dyn_enable_post_data_reading=", var_export(ini_get($e), true), "\n";
echo "lit_enable_post_data_reading=", var_export(ini_get('enable_post_data_reading'), true), "\n";
echo "dyn_memory_limit=", ini_get('memory_limit'), "\n";
echo "dyn_post_max_size=", ini_get('post_max_size'), "\n";
$all = ini_get_all(null, false);
echo "all_file_uploads=", var_export($all['file_uploads'], true), "\n";
echo "all_max_file_uploads=", var_export($all['max_file_uploads'], true), "\n";
echo "pid=", getmypid(), " sapi=", PHP_SAPI, "\n";
