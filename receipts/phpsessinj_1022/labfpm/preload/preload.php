<?php
class Evil {
    public function __wakeup() {
        file_put_contents('/tmp/opencode/research/phpsessinj_1792633613/labfpm/PRELOAD_MARK.txt', "wakeup:".get_class($this)."\n", FILE_APPEND);
    }
}
function evil_cb($c) {
    file_put_contents('/tmp/opencode/research/phpsessinj_1792633613/labfpm/PRELOAD_MARK.txt', "callback:$c\n", FILE_APPEND);
}
