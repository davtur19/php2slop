<?php
header('Content-Type: text/plain');
echo "D:file_uploads=", var_export(ini_get('file_uploads'), true), "\n";
$a = ini_get_all(null, false);
echo "D:all=", var_export($a['file_uploads'] ?? 'MISSING', true), "\n";
echo "D:ini_file=", var_export(php_ini_loaded_file(), true), "\n";
echo "D:script=", $_SERVER['SCRIPT_FILENAME'] ?? '', "\n";
echo "D:uri=", $_SERVER['REQUEST_URI'] ?? '', "\n";
echo "D:pid=", getmypid(), "\n";
echo "D:files=", implode(',', get_included_files()), "\n";
if (function_exists('opcache_get_status')) {
  $s = @opcache_get_status(false);
  echo "D:opcache=", $s ? 'on' : 'off', "\n";
  if ($s && !empty($s['scripts'])) {
     foreach ($s['scripts'] as $k => $v) { if (strpos($k, 'docroot/index') !== false || strpos($k, 'docroot/diag') !== false) echo "D:opc_script=$k ts=", $v['timestamp'] ?? '?', "\n"; }
  }
}
