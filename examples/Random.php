<?php

declare(strict_types=1);

use CQ\Crypto\Random;

try {
    $random = Random::string(
        length: 32
    );
} catch (\Throwable $th) {
    echo $th->getMessage();
    exit;
}

echo json_encode([
    'random' => $random,
]);
