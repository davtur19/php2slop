<?php
header('Content-Type: text/plain');

class T2C implements SessionHandlerInterface {
    public function open($path, $name): bool { return true; }
    public function close(): bool {
        error_log("T2_CLOSE_BAIL pid=".getmypid());
        exit(0);
    }
    public function read($id): string|false { return ''; }
    public function write($id, $data): bool { return true; }
    public function destroy($id): bool { return true; }
    public function gc($max_lifetime): int|false { return 0; }
}

session_set_save_handler(new T2C(), true);
session_id('t2prod2');
session_start();
$_SESSION['x'] = str_repeat('C', 1024);
echo "T2_PRODUCER_CLOSE pid=".getmypid()." sid=".session_id()." status=".session_status()."\n";
