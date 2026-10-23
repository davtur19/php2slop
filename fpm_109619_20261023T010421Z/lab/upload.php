<?php
echo "pid=", getmypid(),
     " post=", count($_POST),
     " files=", count($_FILES),
     " cl=", var_export($_SERVER['CONTENT_LENGTH'] ?? null, true),
     " te=", var_export($_SERVER['HTTP_TRANSFER_ENCODING'] ?? null, true),
     " reql=", var_export($_SERVER['REQUEST_LENGTH'] ?? null, true), "\n";
