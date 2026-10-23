<?php
echo "SID=", session_id(), " STATUS=", session_status(), "\n";
if (isset($GLOBALS['_SESSION'])) { echo "GLOBALS_SESSION:\n"; var_dump($GLOBALS['_SESSION']); } else { echo "NO GLOBALS_SESSION\n"; }
echo "KEYS=", implode(",", array_keys($GLOBALS)), "\n";
