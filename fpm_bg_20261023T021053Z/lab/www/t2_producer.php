<?php
header('Content-Type: text/plain');

class T2Handler implements SessionHandlerInterface {
    public function open($path, $name): bool { return true; }
    public function close(): bool { return true; }
    public function read($id): string|false { return ''; }
    public function write($id, $data): bool { return true; }
    public function destroy($id): bool { return true; }
    public function gc($max_lifetime): int|false { return 0; }
}
class T2BailHandler extends T2Handler {
    public function write($id, $data): bool {
        error_log("T2_WRITE_BAIL pid=".getmypid()." id=".$id." len=".strlen($data));
        exit(0);
    }
    public function close(): bool {
        error_log("T2_CLOSE pid=".getmypid());
        return true;
    }
}

session_set_save_handler(new T2BailHandler(), true);
session_id('t2prod1');
session_start();
$_SESSION['x'] = str_repeat('B', 1024);
echo "T2_PRODUCER pid=".getmypid()." sid=".session_id()." status=".session_status()."\n";
