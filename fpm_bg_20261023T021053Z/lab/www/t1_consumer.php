<?php
header('Content-Type: text/plain');

// Faithful replica of Moodle's session shape:
//   core\session\manager::start() / init_empty_session()
//   lib/classes/session/manager.php:185-186, 292, 310-311
if (isset($_GET['sid'])) {
    session_id($_GET['sid']);
}
session_start();

if (!isset($GLOBALS['USER']) || !is_object($GLOBALS['USER'])) {
    $GLOBALS['USER'] = new \stdClass();
}
$_SESSION['USER'] =& $GLOBALS['USER'];

if (!isset($GLOBALS['SESSION']) || !is_object($GLOBALS['SESSION'])) {
    $GLOBALS['SESSION'] = new \stdClass();
}
$_SESSION['SESSION'] =& $GLOBALS['SESSION'];

echo "T1_CONSUMER pid=".getmypid()
    ." status=".session_status()
    ." sid=".session_id()
    ." keys=".json_encode(array_keys($_SESSION))
    ." USER=".get_class($_SESSION['USER'])
    ." SESSION=".get_class($_SESSION['SESSION'])."\n";
