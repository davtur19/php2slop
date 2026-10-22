<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
foreach ([26,27] as $id){$p=get_post($id); $c=$p->post_content; echo "form $id len=".strlen($c)."\n"; echo "head=".substr($c,0,120)."\n"; echo "tail=".substr($c,-600)."\n"; echo "checkboxes=".substr_count($c,'[checkbox')." multistep=".substr_count($c,'[multistep')."\n";}
