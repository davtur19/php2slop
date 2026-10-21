<?php
session_start();
echo "t1=", var_export(ini_get('file_uploads'), true), "\n";
