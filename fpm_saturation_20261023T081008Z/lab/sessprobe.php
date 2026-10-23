<?php
session_start();
echo "SID=", session_id(), " STATUS=", session_status(), "\n";
echo "SESSION=", json_encode($_SESSION), "\n";
if (isset($GLOBALS['_SESSION'])) { echo "GLOBALS_SESSION=yes\n"; } else { echo "GLOBALS_SESSION=no\n"; }
echo "KEYS=", implode(",", array_keys($GLOBALS)), "\n";
