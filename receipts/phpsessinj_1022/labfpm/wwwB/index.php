<?php
require __DIR__.'/gadget.php';   // simulates composer autoload before middleware
session_start();
echo "B session keys: ".implode(',', array_keys($_SESSION))."\n";
