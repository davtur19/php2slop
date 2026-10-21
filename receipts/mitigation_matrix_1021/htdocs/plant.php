<?php
session_start();
$_SESSION['marker'] = 'GOOD';
echo "PLANTED|S:", count($_SESSION);
