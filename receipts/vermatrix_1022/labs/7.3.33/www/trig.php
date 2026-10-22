<?php
session_write_close();
session_start();
echo "PID=", getmypid(), " STATUS=", session_status(), "\n";
