<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
$id=36; $cf=WPCF7_ContactForm::get_instance($id); $p=$cf->get_properties();
$p['form']="[textarea* bigfield maxlength:99999999]\n\n[multistep multistep-1 first_step \"http://127.0.0.1:28891/oc-cf7-step2/\"]\n\n[submit \"Next\"]\n";
$cf->set_properties($p); $cf->save(); echo "saved\n"; echo $cf->prop('form');
