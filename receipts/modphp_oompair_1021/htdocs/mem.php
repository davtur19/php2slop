<?php
// OOM producer stub: allocate n bytes, echo actual length.
// Lab usage as application-level producer variant (fpm-style path); on mod_php
// the chain is app-independent and this file exists only as a control/probe.
$n = isset($_GET['n']) ? (int)$_GET['n'] : 0;
$s = str_repeat("A", $n);
echo strlen($s), "\n";
