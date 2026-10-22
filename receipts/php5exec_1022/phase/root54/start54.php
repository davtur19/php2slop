<?php
session_start();
echo "SID=".session_id()." STATUS=".session_status()." SER=".ini_get('session.serialize_handler')."\n";
