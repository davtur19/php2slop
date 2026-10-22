<?php
ini_set('memory_limit', '2M');
$plugin = dirname(__DIR__, 2) . '/plugins/hex-coupon-for-woocommerce';
require_once $plugin . '/app/Core/Lib/SingleTon.php';
require_once $plugin . '/app/Core/Helpers/LoyaltyProgram/LoyaltyProgramHelpers.php';
$ref = new ReflectionClass('HexCoupon\\App\\Core\\Helpers\\LoyaltyProgram\\LoyaltyProgramHelpers');
$obj = $ref->newInstanceWithoutConstructor();
$obj->start_session();
echo "PLANT_OK\n";
