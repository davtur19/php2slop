<?php
foreach (["display_errors","memory_limit","post_max_size","upload_max_filesize",
          "max_execution_time","output_buffering","max_input_vars",
          "session.upload_progress.enabled","session.save_path"] as $k)
    echo $k, "=", var_export(ini_get($k), true), "\n";
echo "sapi=", php_sapi_name(), "\n";
