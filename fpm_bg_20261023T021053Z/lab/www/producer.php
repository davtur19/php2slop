<?php
header('Content-Type: text/plain');
error_log("PRODUCER_START pid=".getmypid()." inc=".__FILE__);
class BgBomb { public function __wakeup() { trigger_error("BGBOMB_E_USER_ERROR", E_USER_ERROR); } }
$r = unserialize('O:6:"BgBomb":0:{}');
error_log("PRODUCER_AFTER_UNSERIALIZE pid=".getmypid()." r=".var_export($r,true));
echo "SHOULD_NOT_REACH\n";
