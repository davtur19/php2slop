<?php
require_once __DIR__ . '/wp-load.php';
$plugin = __DIR__ . '/wp-content/plugins/hex-coupon-for-woocommerce';
require_once $plugin . '/app/Core/Lib/SingleTon.php';
require_once $plugin . '/app/Core/Helpers/LoyaltyProgram/LoyaltyProgramHelpers.php';
$ref = new ReflectionClass('HexCoupon\\App\\Core\\Helpers\\LoyaltyProgram\\LoyaltyProgramHelpers');
$obj = $ref->newInstanceWithoutConstructor();
$obj->start_session();
echo "HEXTRIGGER_OK\n";
