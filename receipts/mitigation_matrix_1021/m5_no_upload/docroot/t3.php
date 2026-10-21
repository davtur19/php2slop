<?php
session_start();
echo "t3-post=", var_export($_POST, true), "\n";
echo "t3-files=", var_export($_FILES, true), "\n";
echo "t3=", var_export(ini_get('file_uploads'), true), "\n";
