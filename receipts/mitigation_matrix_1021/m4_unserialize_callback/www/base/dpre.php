<?php
header('Content-Type: text/plain');
class D3 {
    public function __destruct() {
        file_put_contents('/tmp/opencode/m4_test_1021/predefined_marker.txt', 'hit ' . date('c') . "\n", FILE_APPEND);
    }
}
echo "class_before=", var_export(class_exists('D3', false), true), "\n";
$x = unserialize('O:2:"D3":0:{}');
echo "result_class=", is_object($x) ? get_class($x) : gettype($x), "\n";
echo "class_after=", var_export(class_exists('D3', false), true), "\n";
