<?php
header('Content-Type: text/plain');
ini_set('memory_limit', '64M');

if (isset($_GET['sid'])) {
    session_id($_GET['sid']);
}
session_start();
$GLOBALS['USER'] = new \stdClass();
$_SESSION['USER'] =& $GLOBALS['USER'];
$GLOBALS['SESSION'] = new \stdClass();
$_SESSION['SESSION'] =& $GLOBALS['SESSION'];

class T1SameBomb {
    public $big;
    public $ref;
    public function __construct() {
        $this->big = str_repeat('A', 20 * 1024 * 1024);
        $this->ref =& $this->big;
    }
    public function __destruct() {
        ini_set('memory_limit', '24M');
        error_log("T1_SAME_DTOR pid=".getmypid()." mem=".memory_get_usage(true)." limit=".ini_get('memory_limit'));
        $s = serialize([$this->ref, $this->big]);
        error_log("T1_SAME_DTOR_AFTER len=".strlen($s));
    }
}
$GLOBALS['t1same'] = new T1SameBomb();
echo "T1_SAME pid=".getmypid()." sid=".session_id()." keys=".json_encode(array_keys($_SESSION))."\n";
