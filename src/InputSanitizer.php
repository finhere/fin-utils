<?php

declare(strict_types=1);

namespace WebsecUtils;

/**
 * InputSanitizer
 *
 * A small, dependency-free helper for applying a few common request-hygiene
 * checks in front of request handlers that take a file path, template name, or
 * similar identifier from the query string.
 *
 * It is intentionally lightweight. It does not aim to replace a real WAF, an
 * IDS, or framework-level validation. It performs three jobs:
 *
 *   1. Rejects requests whose User-Agent matches a short list of noisy
 *      automated clients (content scanners, fuzzers), to cut log spam.
 *   2. Applies a simple per-IP request budget, to slow brute-force style
 *      enumeration.
 *   3. Inspects a configurable set of "path-bearing" query parameters for
 *      path-traversal / scheme-prefix signatures after normalisation.
 *
 * Typical usage is a single call at the top of a front controller; see the
 * README and the examples/ directory.
 *
 * @package WebsecUtils
 */
final class InputSanitizer
{
    /** @var string[] Query parameters treated as path-bearing and inspected. */
    private array $guardedParams;

    /** @var string[] PCRE patterns that mark a normalised value as hostile. */
    private array $denyPatterns;

    /** @var string[] Case-insensitive User-Agent substrings that are refused. */
    private array $blockedAgents;

    private int $rateMax;
    private int $rateWindow;
    private string $storageDir;

    /**
     * @param array $config Optional overrides. Recognised keys:
     *                      guarded_params, deny_patterns, blocked_agents,
     *                      rate_max, rate_window, storage_dir.
     */
    public function __construct(array $config = [])
    {
        $this->guardedParams = $config['guarded_params'] ?? [
            'doc', 'file', 'path', 'page', 'template', 'include', 'view',
        ];

        $this->denyPatterns = $config['deny_patterns'] ?? [
            '#\.\.[/\\\\]#',
            '#\x00#',
            '#^\s*[/\\\\]#',
            '#^[a-z][a-z0-9+.\-]*://#i',
        ];

        $this->blockedAgents = $config['blocked_agents'] ?? [
            'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'feroxbuster', 'dirb',
            'nikto', 'sqlmap', 'nmap', 'masscan', 'hydra', 'dirsearch',
            'wpscan', 'nuclei', 'zgrab', 'httrack',
        ];

        $this->rateMax    = (int) ($config['rate_max']    ?? 80);
        $this->rateWindow = (int) ($config['rate_window'] ?? 60);
        $this->storageDir = (string) ($config['storage_dir'] ?? sys_get_temp_dir() . '/websec-utils');
    }

    /**
     * Run all checks. Terminates the request with an error response on the
     * first failure; returns normally if every check passes.
     */
    public function protect(): void
    {
        $this->throttle();
        $this->inspect();
    }

    /**
     * Reduce an encoded value to the form the filesystem would ultimately see,
     * so the deny patterns can be matched against a canonical string.
     */
    private function normalise(string $s): string
    {
        $prev = '';
        for ($i = 0; $i < 6 && $s !== $prev; $i++) {
            $prev = $s;
            $s = rawurldecode($s);
        }
        $s = str_replace('\\', '/', $s);
        $s = str_replace(["\r", "\n", "\t"], '', $s);
        return $s;
    }

    /**
     * Parse the raw query string into a flat name => value map.
     *
     * A minimal parser is used rather than parse_str() because we only need a
     * flat lookup of the parameters we guard and do not want array/nested-key
     * handling.
     */
    private function parseQuery(string $qs): array
    {
        $out = [];
        foreach (explode('&', $qs) as $pair) {
            if ($pair === '') {
                continue;
            }
            $eq   = strpos($pair, '=');
            $name = $eq === false ? $pair : substr($pair, 0, $eq);
            $val  = $eq === false ? ''   : substr($pair, $eq + 1);
            $name = urldecode($name);
            $out[$name] = $val;
        }
        return $out;
    }

    /**
     * Inspect each guarded parameter; block on any traversal/scheme signature.
     */
    private function inspect(): void
    {
        $params = $this->parseQuery($_SERVER['QUERY_STRING'] ?? '');
        foreach ($this->guardedParams as $name) {
            if (!isset($params[$name])) {
                continue;
            }
            $value = $this->normalise($params[$name]);
            foreach ($this->denyPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    $this->block(403, 'Request blocked by security policy.');
                }
            }
        }
    }

    /**
     * Refuse scanner User-Agents and enforce a per-IP request budget.
     */
    private function throttle(): void
    {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        if ($ua === '') {
            $this->block(404, 'Not found.');
        }
        foreach ($this->blockedAgents as $sig) {
            if (strpos($ua, $sig) !== false) {
                $this->block(404, 'Not found.');
            }
        }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'anon';
        if (!is_dir($this->storageDir)) {
            @mkdir($this->storageDir, 0750, true);
        }
        $file = $this->storageDir . '/g_' . hash('sha256', $ip) . '.json';
        $now  = time();
        $slot = ['n' => 0, 'reset' => $now + $this->rateWindow];
        if (is_file($file)) {
            $raw = @file_get_contents($file);
            $dec = $raw ? json_decode($raw, true) : null;
            if (is_array($dec) && $now <= ($dec['reset'] ?? 0)) {
                $slot = $dec;
            }
        }
        $slot['n']++;
        @file_put_contents($file, json_encode($slot), LOCK_EX);
        if ($slot['n'] > $this->rateMax) {
            header('Retry-After: ' . max(1, ($slot['reset'] ?? $now) - $now));
            $this->block(429, 'Too many requests.');
        }
    }

    private function block(int $status, string $message): void
    {
        http_response_code($status);
        header('Content-Type: text/plain');
        echo $message;
        exit;
    }
}
