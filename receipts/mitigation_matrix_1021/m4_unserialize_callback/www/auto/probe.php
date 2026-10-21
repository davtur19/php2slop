<?php
header('Content-Type: text/plain');
echo "PHP_VERSION=", PHP_VERSION, "\n";
echo "SAPI=", PHP_SAPI, "\n";
$all = ini_get_all(null, true);
foreach (['unserialize_callback_func','include_path','session.auto_start','session.upload_progress.enabled','session.save_path','user_ini.filename'] as $k) {
    $a = $all[$k] ?? null;
    echo $k, "=", var_export(ini_get($k), true), " access=", $a ? $a['access'] : 'n/a', "\n";
}
$old = ini_set('unserialize_callback_func', 'strlen');
echo "ini_set(unserialize_callback_func,strlen)=", var_export($old, true), "\n";
echo "after=", var_export(ini_get('unserialize_callback_func'), true), "\n";
echo "DOCUMENT_ROOT=", var_export($_SERVER['DOCUMENT_ROOT'] ?? null, true), "\n";
