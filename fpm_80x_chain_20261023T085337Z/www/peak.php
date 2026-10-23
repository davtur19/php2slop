<?php printf("PEAK=%d POST=%d FILES=%d MEM=%d LIMIT=%s\n", memory_get_peak_usage(true), count($_POST), count($_FILES), memory_get_usage(true), ini_get('memory_limit'));
