<?php $s=isset($_GET['s'])?(int)$_GET['s']:5; if($s<0)$s=0; if($s>60)$s=60; usleep($s*1000000); echo "slept ".getmypid()."\n";
