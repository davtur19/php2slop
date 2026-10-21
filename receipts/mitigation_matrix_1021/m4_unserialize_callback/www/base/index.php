<?php
header('Content-Type: text/plain');
echo "SCRIPT_RAN\n";
echo "class_D2_at_script=", var_export(class_exists('D2', false), true), "\n";
echo "session_status=", session_status(), "\n";
