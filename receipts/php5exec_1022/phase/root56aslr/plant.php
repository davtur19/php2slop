<?php
class P5Bomb implements Serializable {
  public function serialize() { return ''; }
  public function unserialize($data) { trigger_error('p5boom', E_USER_ERROR); }
}
$pad = str_repeat('P', 0x100000);
unserialize('C:6:"P5Bomb":0:{}');
echo "plant-alive\n";
