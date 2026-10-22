<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
foreach ([26,27] as $id){$c=get_post($id)->post_content; preg_match_all('/\[multistep[^\]]*\]/',$c,$m); echo "$id: "; print_r($m[0]);}
