<?php
session_start();
echo "S:", count($_SESSION),
     "|M:", var_export($_SESSION['marker'] ?? null, true),
     "|K:", implode(',', array_keys($_SESSION));
