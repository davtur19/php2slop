<?php
echo "trigger-alive status=".session_status()."\n";
if (session_status() === PHP_SESSION_ACTIVE) { echo "SID=".session_id()."\n"; var_export($_SESSION); echo "\n"; }
