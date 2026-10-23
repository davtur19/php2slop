<?php
header('Content-Type: text/plain');
$s = 'a:2:{i:0;s:5:"hello";i:1;R:2;}';
$x = unserialize($s);
echo "DECODED=".json_encode($x)."\n";
$x[1] = 'changed';
echo "AFTER_SET[0]=".$x[0]." [1]=".$x[1]."\n";
echo "REENCODED=".serialize($x)."\n";
$y = ['a' => 1];
$y['b'] = &$y['a'];
echo "OBJ=".serialize($y)."\n";
