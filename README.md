# websec-utils

A small collection of dependency-free PHP helpers for routine web-application
input hygiene. No frameworks, no Composer dependencies, no autoloader required
beyond a single `require`. Intended to be copied into a project or included
directly.

The library currently provides one class, `InputSanitizer`, described in detail
below. Additional helpers may be added over time; each is self-contained and can
be used in isolation.

- [Requirements](#requirements)
- [Installation](#installation)
- [Overview](#overview)
- [Class reference: `InputSanitizer`](#class-reference-inputsanitizer)
  - [Constructor](#constructor)
  - [Configuration options](#configuration-options)
  - [`protect()`](#protect)
  - [Behaviour in detail](#behaviour-in-detail)
- [Usage examples](#usage-examples)
- [Response codes](#response-codes)
- [Storage and rate-limit state](#storage-and-rate-limit-state)
- [Limitations and non-goals](#limitations-and-non-goals)
- [Frequently asked questions](#frequently-asked-questions)
- [Versioning](#versioning)
- [License](#license)

## Requirements

- PHP 7.4 or later (8.x recommended). The code uses typed properties and the
  null-coalescing operator.
- No PHP extensions are required beyond the defaults (`hash`, `json`, and the
  standard string/filesystem functions, all of which ship enabled in a stock
  PHP build).
- A writable directory for rate-limit state (see
  [Storage and rate-limit state](#storage-and-rate-limit-state)). By default the
  system temporary directory is used.

## Installation

There is no package. Copy `src/InputSanitizer.php` into your project and require
it:

```php
require __DIR__ . '/src/InputSanitizer.php';
```

The class lives in the `WebsecUtils` namespace, so reference it as
`\WebsecUtils\InputSanitizer` or import it with a `use` statement.

## Overview

`InputSanitizer` is designed to sit at the very top of a front controller, before
any application logic runs. A single call to `protect()` performs three checks in
sequence:

1. **User-Agent screening.** Requests whose `User-Agent` header matches a short
   list of well-known automated clients (content scanners and fuzzers) are
   refused. This is primarily a log-noise-reduction measure; it is not a security
   control and should not be relied on as one.
2. **Per-IP rate limiting.** A simple fixed-window counter is maintained per
   client IP. Requests beyond the configured budget within the window receive a
   `429 Too Many Requests` response with a `Retry-After` header.
3. **Path-parameter inspection.** A configurable set of query-string parameters
   that are expected to carry a file path, template name, or similar identifier
   are normalised and checked against a list of deny patterns (directory
   traversal, absolute paths, and URL scheme prefixes).

If every check passes, `protect()` returns and the application continues as
normal. If any check fails, the request is terminated immediately with an
appropriate status code and a short plain-text message.

## Class reference: `InputSanitizer`

### Constructor

```php
public function __construct(array $config = [])
```

All behaviour is configured through a single associative array passed to the
constructor. Every key is optional; sensible defaults are applied for any key
that is omitted. Passing no argument at all yields a working instance with the
default configuration.

### Configuration options

| Key | Type | Default | Description |
|---|---|---|---|
| `guarded_params` | `string[]` | `['doc', 'file', 'path', 'page', 'template', 'include', 'view']` | The query-string parameter names that are treated as path-bearing and inspected. Parameters not in this list are not inspected. |
| `deny_patterns` | `string[]` | see below | PCRE patterns applied to each guarded parameter's normalised value. A match causes the request to be rejected. |
| `blocked_agents` | `string[]` | a list of common scanners | Case-insensitive substrings matched against the `User-Agent` header. |
| `rate_max` | `int` | `80` | Maximum number of requests permitted per IP within one window. |
| `rate_window` | `int` | `60` | Length of the rate-limit window, in seconds. |
| `storage_dir` | `string` | system temp dir + `/websec-utils` | Directory in which per-IP counters are stored. |

The default deny patterns are:

| Pattern | Rejects |
|---|---|
| `#\.\.[/\\\\]#` | Directory traversal sequences (`../` or `..\`). |
| `#\x00#` | Embedded null bytes. |
| `#^\s*[/\\\\]#` | Absolute paths (leading slash or backslash). |
| `#^[a-z][a-z0-9+.\-]*://#i` | URL scheme prefixes (e.g. `http://`, `php://`). |

### `protect()`

```php
public function protect(): void
```

Runs the User-Agent screen, the rate limiter, and the parameter inspection, in
that order. On the first failure, the request is terminated (the method does not
return). On success, the method returns `void` and execution continues.

### Behaviour in detail

**Parameter inspection.** Only the parameters named in `guarded_params` are
inspected. For each such parameter present in the query string, the value is
normalised and then tested against every deny pattern. Normalisation repeatedly
URL-decodes the value (up to six passes, stopping early once it stops changing),
converts backslashes to forward slashes, and strips carriage returns, line
feeds, and tabs. The intent is to compare against the form the value would take
once resolved, rather than its raw encoded form.

The query string is parsed with a small built-in parser rather than `parse_str()`,
because only a flat name-to-value lookup of the guarded parameters is required and
the array/nested-key semantics of `parse_str()` are unnecessary here.

**Rate limiting.** State is kept in one small JSON file per client IP, named by a
SHA-256 hash of the address, inside `storage_dir`. The window is fixed: the first
request starts a window of `rate_window` seconds, and the counter resets once the
window elapses. This is deliberately simple and is adequate for discouraging
casual enumeration; it is not a distributed or sliding-window limiter.

**User-Agent screening.** The check is a plain case-insensitive substring match.
An empty `User-Agent` is also refused, as legitimate browsers always send one.

## Usage examples

Minimal, with defaults:

```php
require __DIR__ . '/src/InputSanitizer.php';

(new \WebsecUtils\InputSanitizer())->protect();

// ... application continues here ...
```

Guarding a single parameter with a dedicated storage directory:

```php
require __DIR__ . '/src/InputSanitizer.php';

(new \WebsecUtils\InputSanitizer([
    'guarded_params' => ['doc_id'],
    'storage_dir'    => __DIR__ . '/../var/ratelimit',
]))->protect();
```

Tuning the rate limit:

```php
(new \WebsecUtils\InputSanitizer([
    'rate_max'    => 120,
    'rate_window' => 30,
]))->protect();
```

See the `examples/` directory for a complete front-controller snippet.

## Response codes

| Code | Condition | Body |
|---|---|---|
| `403 Forbidden` | A guarded parameter matched a deny pattern. | `Request blocked by security policy.` |
| `404 Not Found` | The `User-Agent` was empty or matched a blocked agent. | `Not found.` |
| `429 Too Many Requests` | The per-IP request budget was exceeded. A `Retry-After` header is included. | `Too many requests.` |

Bodies are intentionally terse and uniform so as not to disclose which specific
check was triggered.

## Storage and rate-limit state

The rate limiter writes one file per client IP into `storage_dir`. Files are
small JSON documents containing a counter and a reset timestamp. The directory is
created automatically (mode `0750`) if it does not exist. Ensure the web-server
user has write access to this location. The files are safe to delete at any time;
doing so simply resets the counters.

If you deploy multiple application servers behind a load balancer, note that the
counter is local to each server's filesystem and is therefore per-server, not
global. For a shared limit, point `storage_dir` at shared storage or replace the
limiter with a centralised one.

## Limitations and non-goals

This library is intentionally small and has firm boundaries:

- It is **not** a web application firewall. It inspects a fixed set of named
  parameters for a fixed set of patterns and does nothing else. It does not
  inspect POST bodies, headers, cookies, or JSON payloads.
- It is **not** a replacement for correct application-level validation. Handlers
  that consume a path should still validate and canonicalise it themselves.
- The rate limiter is a simple fixed-window counter and makes no attempt to be
  precise at window boundaries or resistant to distributed clients.
- The User-Agent screen is trivially spoofable and exists only to reduce log
  noise from unsophisticated automated traffic.

Treat it as one thin layer among several, not as a boundary you can lean on.

## Frequently asked questions

**Does this protect against SQL injection or XSS?**
No. It only looks at path-bearing query parameters for traversal/scheme
signatures. Use prepared statements and output encoding for those concerns.

**Why not use an existing WAF or a framework's validation layer?**
If you have one, use it. This exists for small PHP apps that have neither and
want a couple of cheap checks without pulling in dependencies.

**Can I inspect parameters other than the defaults?**
Yes. Set `guarded_params` to the list you want. Only the names you list are
inspected.

**Why does it return 404 for blocked scanners instead of 403?**
A 404 is less informative to an automated client than a 403 and tends to produce
fewer retries. This is a cosmetic choice, not a security one.

## Versioning

This project follows semantic versioning. The public surface is the constructor
configuration array and the `protect()` method; changes to either that are not
backwards compatible will be released under a new major version.

## License

MIT. See [LICENSE](LICENSE).
