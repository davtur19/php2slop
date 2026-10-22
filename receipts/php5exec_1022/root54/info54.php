<?php
echo "SID=".session_id()." STATUS=".session_status()."\n";
echo "SER=".ini_get('session.serialize_handler')."\n";
