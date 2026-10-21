<?php
sleep(2);
header('Content-Type: text/plain');
echo "slept pid=" . getmypid() . "\n";
