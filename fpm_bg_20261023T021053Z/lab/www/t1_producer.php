<?php
header('Content-Type: text/plain');
ini_set('memory_limit', '32M');

class T1Bomb {
    public $big;
    public function __construct() {
        $this->big = str_repeat('A', 20 * 1024 * 1024);
        error_log("T1_PRE pid=".getmypid()." mem=".memory_get_usage(true)." limit=".ini_get('memory_limit'));
    }
    public function __destruct() {
        ini_set('memory_limit', '24M');
        error_log("T1_DTOR_START pid=".getmypid()." mem=".memory_get_usage(true)." limit=".ini_get('memory_limit'));
        $s = serialize($this->big);
        error_log("T1_DTOR_AFTER len=".strlen($s));
    }
}

$GLOBALS['t1bomb'] = new T1Bomb();
echo "T1_PRODUCER pid=".getmypid()." ok\n";
