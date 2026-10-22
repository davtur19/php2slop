<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
$u=get_user_by('login','umtestvpqggf');
if(!$u){echo "user missing\n";exit;}
echo "user_id={$u->ID} login={$u->user_login}\n";
$fn=get_user_meta($u->ID,'first_name',true);
echo "first_name_len=".strlen($fn)." prefix=".substr($fn,0,30)."\n";
global $wpdb;
$opt=$wpdb->get_var($wpdb->prepare("SELECT option_value FROM {$wpdb->options} WHERE option_name=%s",'um_cache_userdata_'.$u->ID));
echo "um_cache_len=".strlen($opt)." contains_marker=".(strpos($opt,'FIRST_UMMARK_')!==false?'yes':'no')."\n";
