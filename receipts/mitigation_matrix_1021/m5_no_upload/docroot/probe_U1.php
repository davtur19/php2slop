<?php
header('Content-Type: text/plain');
foreach ([
    'memory_limit', 'post_max_size', 'upload_max_filesize', 'file_uploads',
    'enable_post_data_reading', 'max_file_uploads',
    'session.upload_progress.enabled', 'session.upload_progress.name',
    'session.upload_progress.cleanup', 'session.upload_progress.prefix',
    'session.save_path', 'session.save_handler',
    'display_errors', 'log_errors', 'max_input_time', 'max_execution_time',
] as $k) {
    echo str_pad($k, 38), ' = ', var_export(ini_get($k), true), "\n";
}
echo str_pad('pid', 38), ' = ', getmypid(), "\n";
echo str_pad('sapi', 38), ' = ', PHP_SAPI, "\n";
