<?php
class P54Bomb implements Serializable {
  public function serialize() { return ''; }
  public function unserialize($data) { trigger_error('p54boom', E_USER_ERROR); }
}
$pad = str_repeat('P', 0x100000);
unserialize('C:7:"P54Bomb":0:{}');
echo "plant54-alive\n";
