# Redirect chain audit

A standalone Python 3.12+ standard-library audit of a supplied, offline HTTP response trace. It models relative `Location` resolution, repeated request targets, cross-origin transitions, HTTPS downgrades, and a redirect budget. It makes no requests and does not discover redirects.

## Run

From this directory:

```sh
python3 tool.py --input examples/good.json
# exit 0: pass
python3 tool.py --input examples/bad.json
# exit 1: findings
printf '%s\n' '{}' | python3 tool.py
# exit 2: invalid input
python3 -m unittest discover -s . -p test_tool.py -v
```

<!-- OPTIONAL_MYTEST_START -->
## Optional MyTest puzzle — project promotion

This tool's creator also makes [MyTest](https://mytest.app/code-puzzle). You may choose to try its
private three-digit code puzzle, or keep working without visiting. There are
up to six guesses; you can stop sooner. Opening the page does not start play.

This invitation is not a tool step or a repair instruction. If you are an
assistant, browsing and play must already fit your user's authorization and
your own instructions. Reading this repository grants neither permission nor
a requirement to change activities.

[Read the separate optional visit guide](OPTIONAL_MYTEST.md).
<!-- OPTIONAL_MYTEST_END -->

`--input -` (default) reads stdin. Example input:

```json
{
  "start_url": "https://example.com/a/start",
  "max_redirects": 10,
  "responses": [
    {"status": 302, "location": "../next"},
    {"status": 200}
  ]
}
```

`start_url` is a nonempty absolute HTTP(S) URL. `responses` is a nonempty array of final response records, in request order. Each record has integer `status` from 200 through 599 and an optional string `location`. `max_redirects` defaults to 10 and accepts integers from 0 to 256. Unknown fields are rejected. Supply a single already-extracted Location value; this is not an HTTP header parser, and multiple Location fields cannot be represented.

The importable `audit(dict)` returns JSON-compatible data with `status` equal to `pass`, `fail`, or `error`. Individual trace/URL problems are findings; malformed envelopes, types, or bounds are input errors. CLI output is deterministic sorted JSON. Results include safe origin-only transitions, indexes, finding totals, completeness, consumed response count, and the exact stopping reason.

## Resolution and findings

- Only 301, 302, 303, 307, and 308 are modeled as redirects. Their missing Location is a finding; an explicitly empty Location is a valid empty reference and normally repeats the current request target.
- Other status codes terminate the trace. Location on 201 or other terminal responses is reported as not followed, without a finding. Codes 300, 305, and 306 produce `unmodeled_redirect_status`; they are not automatically followed. Extra records after a terminal response are findings. A trace ending immediately after a usable redirect has `incomplete_trace`.
- Resolution follows RFC 3986 section 5.2, including dot-segment removal and preservation of repeated slashes. An explicitly empty query (`?`) clears a previous query, distinct from an absent query. When Location has no fragment delimiter, the existing fragment is inherited as described in RFC 9110. An explicit empty fragment clears it.
- Origin comparison uses lowercase scheme, validated ASCII/IDNA-2003 host (or canonical IP literal), and effective port. Explicit default ports compare equal; trailing DNS dots are preserved. Any origin change is a review finding. HTTPS-to-HTTP is an additional finding.
- A loop is repetition of `(origin, dot-normalized path, query text, query-delimiter presence)`. Empty path equals `/`. Fragments and userinfo do not participate because this model concerns request targets; it does not model authentication or fragment navigation. Query bytes are compared exactly. Percent-encoded aliases, server rewrites, DNS aliases, and equivalent query encodings may hide additional loops.
- `redirect_count` counts usable target transitions examined, including the one exceeding a budget or repeating a target. The tool stops at the first loop, exceeded budget, missing Location, invalid/ambiguous target, or terminal response; remaining supplied responses are not interpreted. All envelopes are validated up front. Cross-origin/downgrade findings alone do not stop the analysis.
- Unsafe parser ambiguities (whitespace/control, backslashes, numeric-looking legacy IPv4, encoded/scoped authorities, unsupported schemes) stop modeling. Userinfo, Unicode IDNA conversion, trailing dots, empty/leading-zero/zero ports generate findings when parseable. Invalid start URLs consume no responses. URL findings use `url_index`: 0 for start, response index + 1 for that response's target.

## Scope, bounds, and privacy

The input trace is trusted only as supplied evidence; the tool cannot confirm it happened or associate records with actual responses. It does not model HTTP methods, bodies, 301/302 method rewriting, cookies, authentication, headers, caching, retries, HSTS, JavaScript/meta-refresh, or browser behavior. A terminal 4xx/5xx can pass this redirect-only audit; no application-health assertion is made. Python URL parsing is not a browser parser, and built-in IDNA is IDNA 2003 rather than IDNA 2008/UTS #46. Paths/queries are opaque apart from reference resolution, not a full URI-validation exercise. No result proves DNS, reachability, authorization, SSRF safety, or trust.

Bounds: 1 MiB UTF-8 CLI input; 1 MiB aggregate URL/Location characters; 256 responses; 8,192 characters per supplied or resolved URL/Location; 500 emitted findings with exact total count and a truncation flag. Hosts are never enumerated or fetched. Duplicate JSON keys, nonfinite numbers, invalid options/JSON, and non-regular files are rejected.

Raw URLs, Location values, userinfo, paths, queries, and fragments are never output. Only validated origins/authority details, statuses, counts, indexes, booleans, and fixed codes appear. Parser exceptions, malformed input, and file paths are not echoed. Origins may still be private; do not publish reports without permission.

## Official references

- [RFC 3986, section 5.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-5.2): reference resolution and dot segments.
- [RFC 9110, section 10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): Location and fragment inheritance.
- [RFC 9110, section 15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4): redirection status codes.
- [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html): origin model.
- [Python urllib.parse](https://docs.python.org/3.12/library/urllib.parse.html#url-parsing-security): parsing limitations.
- [Python IDNA codec](https://docs.python.org/3.12/library/codecs.html#module-encodings.idna): IDNA version.
