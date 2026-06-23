# Vulnerable http4k Test App

Test application for validating [CodeQL MaD (Models as Data)](https://codeql.github.com/) custom models for the [http4k](https://http4k.org) Kotlin HTTP toolkit. Every endpoint contains an intentional vulnerability that should be detected by CodeQL when the custom model YAML files are applied.

## Stack

- Kotlin 2.2.0 (must stay below 2.3.30 for CodeQL compatibility)
- http4k 6.52.0.0
- JDK 21, Gradle 8.12
- H2 in-memory database (for SQL injection endpoints)

## Project Structure

```
CLAUDE.md                        # Modelling reference, design decisions, format docs
scripts/
  check_findings.py             # Deterministic SARIF assertion harness (CI gate)
  expectations.json             # Expected (must-be-present) / forbidden (must-be-absent) findings
.github/
  codeql/extensions/models/     # 11 custom MaD model YAML files (by module/library)
  workflows/codeql.yml          # CodeQL CI workflow (build-mode: manual) + findings gate
src/main/kotlin/com/example/vulnerable/
  App.kt                        # Route registration (81 endpoints)
  model/UserInput.kt            # Data class for JSON deserialization tests
  routes/
    XssRoutes.kt                # 10 endpoints - reflected XSS
    RedirectRoutes.kt           #  5 endpoints - open redirect
    SsrfRoutes.kt               #  6 endpoints - server-side request forgery
    PathInjectionRoutes.kt      #  2 endpoints - path traversal
    SqlInjectionRoutes.kt       #  7 endpoints - SQL injection
    CommandInjectionRoutes.kt   #  3 endpoints - command injection
    MultipartRoutes.kt          #  2 endpoints - multipart source coverage
    LensRoutes.kt               #  4 endpoints - lens extraction + injection chains
    HeaderRoutes.kt             #  2 endpoints - auth header sources
    UriRoutes.kt                #  2 endpoints - URI/RequestSource sources
    MiscRoutes.kt               #  4 endpoints - parse, curl, params, JSON
    ClientSsrfRoutes.kt         #  4 endpoints - HTTP client SSRF
    LogInjectionRoutes.kt       #  3 endpoints - log injection
    ResponseSplittingRoutes.kt  #  2 endpoints - framework-prevented splitting (negative)
    Result4kRoutes.kt           # 16 endpoints - result4k taint flow (full API coverage)
    TemplateRoutes.kt           #  7 endpoints - Handlebars template XSS/SSTI + http4k Templates
    SanitizerControlRoutes.kt   #  1 endpoint  - barrier control (MUST alert)
    SanitizerRoutes.kt          #  1 endpoint  - barrier treatment (MUST NOT alert)
```

## Custom Model Files

All 11 model files live in `.github/codeql/extensions/models/`, organized by module/library:

| File | Entries | Coverage |
|------|---------|----------|
| `http4k-core.model.yml` | 102 | Request/Response/Uri/Body/Cookie/Credentials sources, sinks, summaries. Form data, cookie extensions, UriKt extensions, parser, curl, UriTemplate, SSRF sinks, Uri.toString/copy summaries (response-splitting sink removed — http4k sanitizes CR/LF) |
| `http4k-lens.model.yml` | 17 | LensExtractor sources, HeaderKt sinks (html-injection, url-redirection), LensInjector.inject sink, Lens/BodyLens/PathLens/LensInjector summaries |
| `http4k-routing.model.yml` | 3 | ExtensionsKt.path source, ResourceLoader.load sink, **resolvedWithinRoot barrier** (path-injection sanitizer) |
| `http4k-filter.model.yml` | 1 | ServerFilters.CatchAll stack trace leak |
| `http4k-multipart.model.yml` | 16 | MultipartFormField, MultipartFormFile, MultipartEntity, MultipartFormBody, MultipartFormBody.from summary |
| `http4k-format.model.yml` | 6 | AutoMarshalling asA/stringAsA/asFormatString/convert, Json.parse |
| `http4k-realtime.model.yml` | 6 | WsMessage body, SseMessage Data/Event |
| `http4k-client.model.yml` | 3 | DualSyncAsyncHttpHandler/AsyncHttpHandler SSRF sinks |
| `http4k-template.model.yml` | 2 | TemplatesKt.renderToResponse/then summaries |
| `handlebars.model.yml` | 10 | Template.apply sinks (html-injection), Handlebars.compileInline sink (template-injection), Context.combine/Template.apply/compileInline summaries |
| `result4k.model.yml` | 18 | Success/Failure constructors and extractors, ResultKt map/flatMap/recover/peek, NullablesKt valueOrNull/asResultOr |

**Total: 184 model entries** (5 source, 6 sink, 8 summary blocks, 1 barrier).

## Expected Findings

74 distinct source-to-sink taint paths across 9 vulnerability categories (73 detected; 81 total
CodeQL alerts), plus negative tests asserting barriers and framework sanitization suppress findings.
The full alert set is locked down deterministically — see Deterministic Testing.

### XSS (CWE-079) — core http4k — 20 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| xss-01 | xssQueryBody | `Request.query()` | `Response.body(String)` | Detected |
| xss-02 | xssBodyStringBody | `Request.bodyString()` | `Response.body(String)` | Detected |
| xss-03 | xssBodyReflect | `Request.bodyString()` | `Response.body(String)` | Detected |
| xss-04 | xssHeaderHtml | `Request.header()` | `HeaderKt.html()` | Detected |
| xss-05 | xssFormBody | `FormBodyKt.form()` | `Response.body(String)` | Detected |
| xss-06 | xssBodyObject | `Request.getBody()` | `Response.body(String)` | Detected |
| xss-07 | xssBodyStream | `Request.getBody()` | `Response.body(Body)` | Detected |
| xss-08 | xssQueriesBody | `Request.queries()` | `Response.body(String)` | Detected |
| xss-09 | xssHeaderValuesBody | `Request.headerValues()` | `Response.body(String)` | Detected |
| xss-10 | xssGetHeadersBody | `HttpMessage.getHeaders()` | `Response.body(String)` | Detected |
| xss-11 | authBasicXss | `HeaderKt.basicAuthentication()` | `Response.body(String)` | Detected |
| xss-12 | uriCredentials | `Uri.credentials()` | `Response.body(String)` | Detected |
| xss-14 | lensQueryExtract | `LensExtractor.invoke()` | `Response.body(String)` | Detected |
| xss-15 | lensBodyExtract | `LensExtractor.invoke()` | `Response.body(String)` | Detected |
| xss-16 | lensExtractorGet | `LensExtractor.extract()` | `Response.body(String)` | Detected |
| xss-17 | lensInjectXss | `Request.query()` | `LensInjector.inject()` | Detected |
| xss-18 | multiFieldXss | `MultipartFormField.getValue()` | `Response.body(String)` | Detected |
| xss-19 | miscParse | `Request.bodyString()` | `Response.body(String)` | Detected |
| xss-20 | miscParams | `Request.getUri()` | `Response.body(String)` | Detected |
| xss-21 | miscJsonConvert | `Request.bodyString()` | `Response.body(String)` | Detected |

**Excluded from count:**
- xss-13 (uriRequestSource): `RequestSource` is modelled as `local` source, not `remote` — CodeQL correctly does not flag it as XSS
- miscCurl: Requires the `Request` object itself to carry taint, which CodeQL doesn't support (only method return values are tainted)

### XSS (CWE-079) — result4k taint propagation — 16 paths (all detected)

Each endpoint wraps `Request.query()` data through a result4k API, then reflects it via an
inline `Response.body(String)` sink (one alert per entry). All 16 fired in CI — every
`result4k.model.yml` entry is validated.

| ID | Function | result4k entry exercised |
|----|----------|--------------------------|
| r4k-01 | result4kSuccessXss | `Success(value)` ctor + `Success.value` |
| r4k-02 | result4kSuccessComponent1 | `Success.component1()` (destructuring) |
| r4k-03 | result4kFailureReason | `Failure(reason)` ctor + `Failure.reason` |
| r4k-04 | result4kFailureComponent1 | `Failure.component1()` (destructuring) |
| r4k-05 | result4kAsSuccess | `ResultKt.asSuccess` |
| r4k-06 | result4kAsFailure | `ResultKt.asFailure` |
| r4k-07 | result4kMapXss | `ResultKt.map` |
| r4k-08 | result4kFlatMap | `ResultKt.flatMap` |
| r4k-09 | result4kMapFailure | `ResultKt.mapFailure` |
| r4k-10 | result4kFlatMapFailure | `ResultKt.flatMapFailure` |
| r4k-11 | result4kRecover | `ResultKt.recover` |
| r4k-12 | result4kOnFailure | `ResultKt.onFailure` |
| r4k-13 | result4kPeek | `ResultKt.peek` |
| r4k-14 | result4kPeekFailure | `ResultKt.peekFailure` |
| r4k-15 | result4kValueOrNullXss | `NullablesKt.valueOrNull` |
| r4k-16 | result4kAsResultOr | `NullablesKt.asResultOr` |

### XSS (CWE-079) — Handlebars templates — 5 paths (4 detected)

| ID | Function | Sink / entry exercised | Status |
|----|----------|------------------------|--------|
| hbs-01 | handlebarsXss | `Template.apply(Object)` html-injection | Detected |
| hbs-02 | handlebarsApplyWriter | `Template.apply(Object,Writer)` html-injection | Detected |
| hbs-03 | handlebarsApplyContext | `Context.combine(String,Object)` summary → `Template.apply(Context)` html-injection | Detected |
| hbs-04 | handlebarsApplyContextMap | `Context.combine(Map)` summary → `Template.apply(Context)` html-injection | Detected |
| hbs-05 | templateRenderToResponse | `TemplatesKt.renderToResponse` html-injection | **Not detected** |

**hbs-05 not detected:** the `renderToResponse` sink model is correct, but CodeQL does not propagate
taint from the `GreetingView(name)` constructor argument through the ViewModel object to the sink
(ViewModel field-flow limitation). The model entry is kept; this is a CodeQL tracking gap, not a
model error — analogous to the `uriRequestSource` / `miscCurl` exclusions.

### URL Redirect (CWE-601) — 6 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| redirect-01 | redirectHeader | `Request.query()` | `Response.header(Location)` | Detected |
| redirect-02 | redirectReplace | `Request.query()` | `Response.replaceHeader(Location)` | Detected |
| redirect-03 | redirectLocation | `Request.query()` | `HeaderKt.location()` | Detected |
| redirect-04 | redirectTemplate | `Request.query()` | `Response.header(Location)` | Detected |
| redirect-05 | redirectCookieSrc | `CookieExtensionsKt.cookie()` | `Response.header(Location)` | Detected |
| redirect-06 | splitHeaderValue | `Request.query()` | `Response.header(name, tainted)` | Detected |

### Template Injection (CWE-1336) — 2 paths

| ID | Function | Source | Sink |
|----|----------|--------|------|
| ssti-01 | handlebarsSsti | `Request.query()` | `Handlebars.compileInline(String)` |
| ssti-02 | handlebarsCompileInlineDelims | `Request.query()` | `Handlebars.compileInline(String,String,String)` |

### SSRF / Request Forgery (CWE-918) — 6 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| ssrf-01 | ssrfUriSet | `Request.query()` | `Request.uri(Uri)` | Detected |
| ssrf-02 | ssrfRequestCreate | `Request.query()` | `Request$Companion.create$default` | Detected |
| ssrf-03 | ssrfExtend | `Request.query()` | `UriKt.extend(Uri)` | Detected |
| ssrf-04 | ssrfRelative | `Request.query()` | `UriKt.relative(String)` | Detected |
| ssrf-05 | ssrfAppendPath | `Request.query()` | `UriKt.appendToPath(String)` | Detected |
| ssrf-06 | ssrfHeaderUrl | `Request.header()` | `Request.uri(Uri)` | Detected |

### Client SSRF (CWE-918) — 4 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| client-01 | ssrfOkHttp | `Request.query()` | `DualSyncAsyncHttpHandler.invoke(Request)` | Detected |
| client-02 | ssrfJettyClient | `Request.header()` | `DualSyncAsyncHttpHandler.invoke(Request)` | Detected |
| client-03 | ssrfOkHttpUri | `Request.query()` | `DualSyncAsyncHttpHandler.invoke(Request)` | Detected |
| client-04 | ssrfOkHttpAsync | `Request.query()` | `AsyncHttpHandler.invoke(Request, callback)` | Detected |

### SQL Injection (CWE-089) — 8 paths

| ID | Function | Source | Sink (built-in) | Status |
|----|----------|--------|------|--------|
| sqli-01 | sqlQuery | `Request.query()` | `Statement.executeQuery()` | Detected |
| sqli-02 | sqlForm | `FormBodyKt.form()` | `Statement.executeQuery()` | Detected |
| sqli-03 | sqlFormMap | `FormBodyKt.formAsMap()` | `Statement.executeQuery()` | Detected |
| sqli-04 | sqlHeader | `Request.header()` | `Statement.executeQuery()` | Detected |
| sqli-05 | sqlCookie | `CookieExtensionsKt.cookie()` | `Statement.executeQuery()` | Detected |
| sqli-06 | sqlBearer | `HeaderKt.bearerToken()` | `Statement.executeQuery()` | Detected |
| sqli-07 | sqlJson | `Request.bodyString()` | `Statement.executeQuery()` | Detected |
| sqli-08 | authBearerSql | `HeaderKt.bearerToken()` | `Statement.executeQuery()` | Detected |

**Note:** sqlQuery/sqlForm/sqlFormMap/sqlHeader share one `executeQuery()` call via `executeUnsafeQuery()`, so CodeQL consolidates them into a single alert at SqlInjectionRoutes.kt:27. The remaining SQL routes have inline queries for independent detection.

### Command Injection (CWE-078) — 3 paths

| ID | Function | Source | Sink (built-in) | Status |
|----|----------|--------|------|--------|
| cmdi-01 | cmdQuery | `Request.query()` | `Runtime.exec()` | Detected |
| cmdi-02 | cmdHeader | `Request.header()` | `Runtime.exec()` | Detected |
| cmdi-03 | cmdBody | `Request.bodyString()` | `Runtime.exec()` | Detected |

### Path Injection (CWE-022) — 3 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| path-01 | pathQuery | `Request.query()` | `ResourceLoader.load()` | Detected |
| path-02 | pathHeader | `Request.header()` | `ResourceLoader.load()` | Detected |
| path-03 | multiFileName | `MultipartFormFile.getFilename()` | `ResourceLoader.load()` | Detected |
| path-04 | pathControlUnsanitized | `Request.query()` | `ResourceLoader.load()` | Pending |

### Negative Tests — Barriers & Framework Sanitization

These assert the **absence** of a finding. A negative test is only meaningful next to a control
that *does* alert and is otherwise identical, so the silence is attributable to the sanitizer.
Verified deterministically by `scripts/check_findings.py` (a passing negative test that lost its
alert for the wrong reason would also lose its control, failing the check).

| Test | Control (MUST alert) | Treatment (MUST NOT alert) | Difference |
|------|----------------------|----------------------------|------------|
| `resolvedWithinRoot` barrier | `pathControlUnsanitized` (SanitizerControlRoutes.kt) | `pathResolvedWithinRoot` (SanitizerRoutes.kt) | `.resolvedWithinRoot()` before `load()` |
| Response splitting (framework) | — (http4k strips CR/LF internally) | `splitHeaderName`, `splitHeaderValue`, redirect endpoints | `Response.header` sanitizes via `withoutCrLf` |

The response-splitting case has no user-callable control because the sanitization is internal to
`Response.header()`; it is documented as a known framework guarantee, and the sink was removed.

### Summary

| Category | Paths | Detected |
|----------|-------|----------|
| XSS — core http4k | 20 | 20 |
| XSS — result4k | 16 | 16 |
| XSS — Handlebars | 5 | 4 (renderToResponse not detected — CodeQL field-flow) |
| Redirect | 6 | 6 |
| Template Injection | 2 | 2 |
| SSRF | 6 | 6 |
| Client SSRF | 4 | 4 |
| SQL Injection | 8 | 8 |
| Command Injection | 3 | 3 |
| Path Injection | 4 | 4 |
| **Total (positive paths)** | **74** | **73** |

| Negative test | Expectation | Result |
|---------------|-------------|--------|
| `pathResolvedWithinRoot` | no `java/path-injection` (barrier) | Suppressed ✓ |
| `ResponseSplittingRoutes` / redirects | no `java/http-response-splitting` (framework CR/LF stripping) | Suppressed ✓ |

73 of 74 positive paths detected (the lone gap, `renderToResponse`, is a CodeQL ViewModel
field-flow limitation, not a model error). Both negative tests pass: the `resolvedWithinRoot`
barrier suppresses path-injection while its identical control still alerts, and response-splitting
is gone (http4k sanitizes CR/LF internally — those were false positives, category removed).

The scan emits **81 CodeQL alerts** total (paths plus bonus XSS on SSRF endpoints and double
alerts where a Handlebars `apply` sink and its rendered-body summary both fire). The exact
per-(rule, file) alert baseline is locked in `scripts/expectations.json` and enforced by CI.

**Bonus findings:** CodeQL also detects secondary alerts from SSRF/client endpoints that echo user input in the response body (XSS). These are true positives not listed above.

**Log injection:** 3 test endpoints exist (LogInjectionRoutes.kt) but `java/log-injection` is not included in CodeQL's default security query suite. The endpoints validate that http4k sources flow into logging sinks if the query is enabled.

## Deterministic Testing

CodeQL cannot run locally (CI only), and eyeballing scan results — especially the *absence* of a
finding — is not reliable. `scripts/check_findings.py` parses the SARIF output and asserts it
against `scripts/expectations.json`:

It is a **closed-world** check over the whole alert set:

- **`counts`** — exact number of alerts per `(rule, file)`. Every one of the 81 alerts is declared;
  a count that drifts (a path regresses 16→15, or a model stops firing) fails the build.
- **`forbidden`** — `(rule, file)` pairs that must be zero (barriers / framework sanitization).
- **undeclared findings** — any alert whose `(rule, file)` is not declared fails the build, so an
  unexpected new finding cannot slip in silently.

Matching is by `ruleId` + file **basename**, which is robust to line-number shifts (rewriting a
file moves alert lines but not counts — this is why the earlier edits showed "closed/new" churn).
Dependency-free (Python 3 stdlib); exits non-zero on any mismatch, so CI fails on regression:

```bash
python3 scripts/check_findings.py sarif-results scripts/expectations.json
```

Run it locally against a downloaded SARIF (`gh run download <run-id> --name codeql-sarif -D sarif-output`)
to reproduce the CI gate. When models/endpoints change, update the baseline counts in
`expectations.json` intentionally — that diff is the record of what changed.

### Key Learnings

- CodeQL's `java/xss` query uses sink kind `"html-injection"`, not `"xss"`
- Kotlin extension functions compile to `<FileName>Kt` static methods; receiver is `Argument[0]`
- Methods with default parameters compile to `$default` variants (e.g., `credentials$default`)
- `Request(GET, url)` compiles to `Request$Companion.create$default`, not `invoke`

## CI Workflow

The GitHub Actions workflow (`.github/workflows/codeql.yml`) runs on every push to `main`:

1. Checks out code
2. Sets up JDK 21
3. Initializes CodeQL with `build-mode: manual`
4. Builds with `./gradlew clean assemble --no-daemon`
5. Runs CodeQL analysis (auto-discovers model files from `.github/codeql/extensions/`)
6. Uploads SARIF as a downloadable artifact (always, even on failure)
7. Runs `scripts/check_findings.py` as a gate — the build fails if expected findings are missing or forbidden findings appear

## Iteration Workflow

```bash
# 1. Push changes
git push origin main

# 2. Watch the workflow run
gh run list --repo 1LNM/vulnerable-http4k-app-2 --limit 1
gh run watch <run-id> --repo 1LNM/vulnerable-http4k-app-2

# 3. Download SARIF results
gh run download <run-id> --repo 1LNM/vulnerable-http4k-app-2 --name codeql-sarif -D ./sarif-output

# 4. Extract findings summary
jq '[.runs[0].results[] | {rule: .ruleId, file: .locations[0].physicalLocation.artifactLocation.uri, line: .locations[0].physicalLocation.region.startLine}]' sarif-output/java-kotlin.sarif

# 5. Or use code scanning alerts API
gh api repos/1LNM/vulnerable-http4k-app-2/code-scanning/alerts --paginate

# 6. Compare expected vs actual, adjust models/code, repeat
```
