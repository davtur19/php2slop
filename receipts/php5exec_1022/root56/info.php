<?php
echo "SID=".session_id()." STATUS=".session_status()."\n";
echo "SER=".ini_get('session.serialize_handler')." UP=".ini_get('session.upload_progress.enabled')."\n";
