<?php
echo "PID=".getmypid()." VER=".PHP_VERSION." SAPI=".PHP_SAPI."\n";
foreach (['display_errors','memory_limit','post_max_size','upload_max_filesize','output_buffering','session.serialize_handler','session.upload_progress.enabled','session.upload_progress.cleanup','max_execution_time','max_input_time','enable_post_data_reading'] as $k) {
  echo $k."=".var_export(ini_get($k),true)."\n";
}
echo "POSTCOUNT=".(isset($_POST)?count($_POST):-1)." CL=".(isset($_SERVER['CONTENT_LENGTH'])?$_SERVER['CONTENT_LENGTH']:'NULL')." TE=".(isset($_SERVER['HTTP_TRANSFER_ENCODING'])?$_SERVER['HTTP_TRANSFER_ENCODING']:'NULL')."\n";
