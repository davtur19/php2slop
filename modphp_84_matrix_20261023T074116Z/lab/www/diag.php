<?php
header('Content-Type: text/plain');
foreach (['display_errors','memory_limit','post_max_size','upload_max_filesize','max_execution_time','session.upload_progress.enabled','output_buffering','zend.assertions'] as $k) echo "$k=", ini_get($k), "\n";
echo "version=", PHP_VERSION, "\n";
