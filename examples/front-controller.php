<?php

declare(strict_types=1);

/**
 * Example: applying InputSanitizer at the top of a front controller.
 *
 * This mirrors a typical small-app layout where a single entry point includes
 * the sanitizer before dispatching to a handler that loads a document by id.
 */

require __DIR__ . '/../src/InputSanitizer.php';

use WebsecUtils\InputSanitizer;

// Run hygiene checks before anything else. Guards the single path-bearing
// parameter this app uses, and keeps rate-limit state under the app's var/ dir.
(new InputSanitizer([
    'guarded_params' => ['doc_id'],
    'storage_dir'    => __DIR__ . '/../var/ratelimit',
]))->protect();

// ---------------------------------------------------------------------------
// Application logic continues below. The sanitizer has already returned, so
// any request that reaches this point passed every check.
// ---------------------------------------------------------------------------

$docId = $_GET['doc_id'] ?? 'index';

echo "Would load document: " . htmlspecialchars((string) $docId, ENT_QUOTES);
