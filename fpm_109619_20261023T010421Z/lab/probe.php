<?php
echo "pid=", getmypid(), "\n";
foreach (["memory_limit","post_max_size","upload_max_filesize","max_execution_time","display_errors","session.upload_progress.enabled","fatal_error_backtraces","session.save_handler"] as $k) echo $k,"=",ini_get($k),"\n";
