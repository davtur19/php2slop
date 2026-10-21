<?php
// urlencoded POST echo: proves whether normal POST endpoints still work.
header('Content-Type: text/plain');
echo "R:method=" . ($_SERVER['REQUEST_METHOD'] ?? '') . "\n";
echo "R:post_keys=" . implode(',', array_keys($_POST)) . "\n";
echo "R:v=" . (isset($_POST['v']) ? $_POST['v'] : '<unset>') . "\n";
echo "R:files=" . count($_FILES) . "\n";
echo "R:content_length=" . ($_SERVER['CONTENT_LENGTH'] ?? '<unset>') . "\n";
echo "R:post_max=" . ini_get('post_max_size') . "\n";
echo "R:mem_limit=" . ini_get('memory_limit') . "\n";
echo "R:pid=" . getmypid() . "\n";
