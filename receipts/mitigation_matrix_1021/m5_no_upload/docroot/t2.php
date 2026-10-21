<?php
session_start();
$upgName = ini_get('session.upload_progress.name');
$upgKey = ini_get('session.upload_progress.prefix') . $upgName;
echo "t2=", var_export(ini_get('file_uploads'), true), "\n";
