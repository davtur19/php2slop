<?php
// Machinery probe: resume an arbitrary session id and report $_FILES seen.
// Any .php script served by mod_php is a valid consumer target for the chain;
// this file just makes the state observable for smokechecks.
if (isset($_GET['sid'])) {
    session_id($_GET['sid']);
}
session_start();
echo session_id(), "\n";
echo !empty($_FILES) ? "files=" . count($_FILES) : "noupload";
echo "\n";
