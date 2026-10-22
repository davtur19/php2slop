<?php
session_start();
echo "type=", gettype($_SESSION['S'] ?? null), " val=", is_string($_SESSION['S'] ?? null) ? $_SESSION['S'] : '?', "\n";
var_dump($_SESSION);
