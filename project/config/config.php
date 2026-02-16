<?php

$env = parse_ini_file(__DIR__ . '/../.env');

define('DB_HOST', $env['DB_HOST']);
define('DB_NAME', $env['DB_NAME']);
define('DB_USER', $env['DB_USER']);
define('DB_PASS', $env['DB_PASS']);

define('JWT_SECRET', $env['JWT_SECRET']);
define('JWT_EXPIRY', $env['JWT_EXPIRY']);
define('AES_SECRET', $env['AES_SECRET']);
define('HASH_SECRET', $env['HASH_SECRET']);

