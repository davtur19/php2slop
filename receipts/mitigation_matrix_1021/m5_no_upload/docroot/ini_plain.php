<?php
echo "plain:file_uploads=", var_export(ini_get('file_uploads'), true), "\n";
echo "plain:method=", $_SERVER['REQUEST_METHOD'] ?? '', "\n";
