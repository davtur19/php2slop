<?php
class Evil {
    public $cmd = 'none';
    public function __destruct() {
        file_put_contents('/tmp/opencode/research/phpsessinj_1792633613/labfpm/POP_FIRED.txt',
            "class=".__CLASS__." cmd=".$this->cmd."\n", FILE_APPEND);
    }
}
spl_autoload_register(function ($c) {
    if ($c === 'Evil') require __DIR__.'/gadget.php';
});
