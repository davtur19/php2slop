<?php
session_start();
$_SESSION['x'] = 'y';
echo "sid=", session_id(), " ok\n";
