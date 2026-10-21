<?php
// Effective-INI probe (lane E). Prints the values actually in force for this
// request plus the INI access level, and tries ini_set() to prove admin scope.
$keys = [
    'session.upload_progress.enabled',
    'session.upload_progress.cleanup',
    'memory_limit',
    'post_max_size',
    'display_errors',
    'fatal_error_backtraces',
    'log_errors',
    'error_log',
    'session.save_path',
    'max_file_uploads',
];
$all = ini_get_all(null, true);
foreach ($keys as $k) {
    $a = $all[$k] ?? null;
    printf("%s=%s access=%s\n", $k, var_export(ini_get($k), true), $a === null ? 'n/a' : $a['access']);
}
// admin-scope proof: ini_set must fail (return false) when the value is
// locked by php_admin_value / php_admin_flag.
foreach ([
    'session.upload_progress.enabled' => '1',
    'memory_limit' => '999M',
    'display_errors' => '1',
    'fatal_error_backtraces' => '1',
] as $k => $v) {
    printf("ini_set:%s=%s\n", $k, var_export(@ini_set($k, $v), true));
}
printf("PHP_VERSION=%s SAPI=%s\n", PHP_VERSION, PHP_SAPI);
