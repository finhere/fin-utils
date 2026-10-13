<?php

declare(strict_types=1);

/**
 * Minimal smoke tests for InputSanitizer.
 *
 * These are plain assertions runnable with `php tests/InputSanitizerTest.php`;
 * no test framework is required. They exercise the normalisation and pattern
 * matching indirectly via reflection, since the methods are private and the
 * class is designed to be used as a single top-level call.
 */

require __DIR__ . '/../src/InputSanitizer.php';

use WebsecUtils\InputSanitizer;

$sanitizer = new InputSanitizer();
$ref = new ReflectionClass($sanitizer);

$normalise = $ref->getMethod('normalise');
$normalise->setAccessible(true);

function check(string $label, bool $cond): void
{
    echo ($cond ? 'PASS' : 'FAIL') . '  ' . $label . PHP_EOL;
}

// normalisation collapses repeated percent-encoding
check(
    'normalise decodes %2e%2e%2f to ../',
    $normalise->invoke($sanitizer, '%2e%2e%2f') === '../'
);

// normalisation converts backslashes
check(
    'normalise converts backslashes to slashes',
    $normalise->invoke($sanitizer, '..\\') === '../'
);

// deny pattern matches traversal
$deny = $ref->getProperty('denyPatterns');
$deny->setAccessible(true);
$patterns = $deny->getValue($sanitizer);
$hitsTraversal = false;
foreach ($patterns as $p) {
    if (preg_match($p, '../')) { $hitsTraversal = true; break; }
}
check('a deny pattern matches ../', $hitsTraversal);

echo 'Done.' . PHP_EOL;
