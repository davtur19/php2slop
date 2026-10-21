<?php
header('Content-Type: text/plain');
echo "class_before=", var_export(class_exists('D2', false), true), "\n";
$x = unserialize('O:2:"D2":0:{}');
echo "result_class=", is_object($x) ? get_class($x) : gettype($x), "\n";
echo "class_after=", var_export(class_exists('D2', false), true), "\n";
