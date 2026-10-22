<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
global $wpdb;
foreach ([23,26,27] as $id) {
  $p=get_post($id); if(!$p){echo "$id missing\n";continue;}
  echo "=== $id {$p->post_title}\n";
  echo substr($p->post_content,0,2000),"\n";
  echo "--- meta\n";
  foreach (get_post_meta($id) as $k=>$v) { if (in_array($k,['_form','_mail','_mail_2','_messages','_additional_settings','_locale'])) echo "$k: ".substr(is_array($v)?json_encode($v):$v[0],0,1500)."\n"; }
}
