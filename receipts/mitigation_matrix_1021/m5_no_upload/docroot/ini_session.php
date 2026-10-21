<?php
echo "before:file_uploads=", var_export(ini_get('file_uploads'), true), "\n";
session_start();
echo "after:file_uploads=", var_export(ini_get('file_uploads'), true), "\n";
