<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
global $wpdb;
echo "active_plugins:\n"; foreach (get_option('active_plugins') as $p) echo "  $p\n";
echo "posts of type wpcf7_contact_form:\n";
foreach ($wpdb->get_results("SELECT ID,post_title,post_status FROM {$wpdb->posts} WHERE post_type='wpcf7_contact_form'") as $p) echo "  {$p->ID} {$p->post_title} {$p->post_status}\n";
echo "pages:\n";
foreach ($wpdb->get_results("SELECT ID,post_name,post_status FROM {$wpdb->posts} WHERE post_type='page' AND post_status='publish'") as $p) echo "  {$p->ID} {$p->post_name}\n";
echo "um forms:\n";
foreach ($wpdb->get_results("SELECT ID,post_title,post_status FROM {$wpdb->posts} WHERE post_type='um_form'") as $p) echo "  {$p->ID} {$p->post_title} {$p->post_status}\n";
