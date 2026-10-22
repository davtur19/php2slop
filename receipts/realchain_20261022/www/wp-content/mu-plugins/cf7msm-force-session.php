<?php
/* Lab configuration: use the free plugin's documented native PHP session fallback. */
add_filter( 'cf7msm_force_session', '__return_true' );
