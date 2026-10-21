<?php
header('Content-Type: text/plain');
$s=@opcache_get_status(true);
echo "enabled=", var_export($s!==false && $s['opcache_enabled'], true), "\n";
echo "num_scripts=", $s['opcache_statistics']['num_cached_scripts'] ?? '?', "\n";
foreach (($s['scripts'] ?? []) as $k=>$v) { if (strpos($k,'fold2')!==false || strpos($k,'index.php')!==false) echo "$k ts=", $v['timestamp'] ?? '?', " hits=", $v['hits'] ?? '?', "\n"; }
