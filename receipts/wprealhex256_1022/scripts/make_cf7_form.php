<?php
require '/tmp/opencode/research/wprealhex_20261022T011837Z/www/wordpress/wp-load.php';
if (!class_exists('WPCF7_ContactForm')) { fwrite(STDERR,"no cf7\n"); exit(1); }
$title = 'OC session step 1';
$existing = get_page_by_title($title, OBJECT, 'wpcf7_contact_form');
$form = "[textarea* bigfield]\n\n[multistep multistep-1 first_step \"http://127.0.0.1:28891/oc-cf7-step2/\"]\n\n[submit \"Next\"]\n";
if ($existing) {
  $cf = WPCF7_ContactForm::get_instance($existing->ID);
  echo "exists id={$existing->ID}\n";
} else {
  $cf = WPCF7_ContactForm::get_template();
  $cf->set_title($title);
  $props = $cf->get_properties();
  $props['form'] = $form;
  $props['mail']['subject'] = 'oc test';
  $props['mail']['recipient'] = 'admin@example.invalid';
  $props['mail']['body'] = 'bigfield=[bigfield]';
  $props['mail']['additional_headers'] = '';
  $props['mail']['attachments'] = '';
  $props['mail']['use_html'] = 0;
  $props['mail']['exclude_blank'] = 0;
  $props['mail_2']['active'] = 0;
  $cf->set_properties($props);
  $id = $cf->save();
  echo "created id=$id\n";
}
$form_id = $existing ? $existing->ID : $id;
$page_title = 'OC CF7 step 1';
$page = get_page_by_title($page_title, OBJECT, 'page');
$content = '[contact-form-7 id="'.$form_id.'" title="OC session step 1"]';
if ($page) { wp_update_post(['ID'=>$page->ID,'post_content'=>$content]); echo "page updated id={$page->ID}\n"; }
else { $pid = wp_insert_post(['post_title'=>$page_title,'post_name'=>'oc-cf7-step1','post_content'=>$content,'post_status'=>'publish','post_type'=>'page']); echo "page created id=$pid\n"; }
