<?php
class D2 {
    public function __destruct() {
        file_put_contents(__DIR__ . '/marker.txt', 'hit ' . date('c') . "\n", FILE_APPEND);
    }
}
