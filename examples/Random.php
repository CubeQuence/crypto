<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use CQ\Crypto\Random;

try {
    $random = Random::string(length: 32);
} catch (\Throwable $error) {
    echo $error->getMessage();
    exit;
}

echo json_encode([
    'random' => $random,
]);
