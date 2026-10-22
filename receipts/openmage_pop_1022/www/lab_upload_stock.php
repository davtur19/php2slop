<?php
/* LAB-ONLY upload sink: deliberately does NOT call session_start().
   The rfc1867 upload-progress handler is the only session user here. */
header('Content-Type: text/plain');
echo "SINK\n";
