<?php
header('Content-Type: text/plain');
echo "fold2:file_uploads=", ini_get('file_uploads'), " max_file_uploads=", ini_get('max_file_uploads'), " pid=", getmypid(), "\n";
