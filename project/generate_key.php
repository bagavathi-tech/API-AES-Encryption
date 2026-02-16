<?php
echo "AES_SECRET=" . bin2hex(random_bytes(32)) . "<br><br>";
echo "HASH_SECRET=" . bin2hex(random_bytes(32));
