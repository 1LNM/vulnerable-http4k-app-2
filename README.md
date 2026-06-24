# Vulnerable http4k Test App

Test application for validating [CodeQL MaD (Models as Data)](https://codeql.github.com/) custom models for the [http4k](https://http4k.org) Kotlin HTTP toolkit. Every endpoint contains an intentional vulnerability that should be detected by CodeQL when the custom model YAML files are applied.

## Stack

- Kotlin 2.2.0 (must stay below 2.3.30 for CodeQL compatibility)
- http4k 6.52.0.0
- JDK 21, Gradle 8.12
- H2 in-memory database (for SQL injection endpoints)

## Project Structure

```
scripts/
  check_findings.py             # Deterministic SARIF assertion harness (CI gate)
  expectations.json             # Expected (must-be-present) / forbidden (must-be-absent) findings
.github/
  codeql/extensions/models/     # 16 custom MaD model YAML files (by module/library)
  workflows/codeql.yml          # CodeQL CI workflow (build-mode: manual) + findings gate
src/main/kotlin/com/example/vulnerable/
  App.kt                        # Route registration (112 endpoints)
  model/UserInput.kt            # Data class for JSON deserialization tests
  routes/                       # 27 route files (one vulnerability family or library each)
```

Route files group by what they exercise: core vulnerability families (`XssRoutes`,
`RedirectRoutes`, `SsrfRoutes`, `ClientSsrfRoutes`, `PathInjectionRoutes`, `SqlInjectionRoutes`,
`CommandInjectionRoutes`, `LogInjectionRoutes`, `MultipartRoutes`, `LensRoutes`, `HeaderRoutes`,
`UriRoutes`, `MiscRoutes`); dependency-library coverage (`Result4kRoutes`, `TemplateRoutes`,
`JsoupRoutes`/`JsoupControlRoutes`, `JacksonRoutes`, `JwtRoutes`, `ArrowRoutes`, `KroutonRoutes`,
`FreeMarkerRoutes`, `CommonsFileUploadRoutes`); negative/barrier tests (`SanitizerRoutes`,
`SanitizerControlRoutes`, `ResponseSplittingRoutes`); and model-verification probes
(`ComparisonPlanRoutes`).

## Custom Model Files

All 16 model files live in `.github/codeql/extensions/models/`, organized by module/library:

| File | Entries | Coverage |
|------|---------|----------|
| `http4k-core.model.yml` | 109 | Request/Response/Uri/Body/Cookie/Credentials sources, sinks, summaries. Form data, cookie extensions, UriKt extensions, parser, curl, UriTemplate, SSRF sinks, Uri.toString/copy summaries, **neutrals** (Filter.invoke, getStatus, getMethod). Response-splitting sink removed — http4k sanitizes CR/LF |
| `http4k-lens.model.yml` | 17 | LensExtractor sources, HeaderKt sinks (html-injection, url-redirection), LensInjector.inject sink, Lens/BodyLens/PathLens/LensInjector summaries |
| `http4k-routing.model.yml` | 3 | ExtensionsKt.path source, ResourceLoader.load sink, **resolvedWithinRoot barrier** (path-injection sanitizer) |
| `http4k-filter.model.yml` | 1 | ServerFilters.CatchAll stack trace leak |
| `http4k-multipart.model.yml` | 16 | MultipartFormField, MultipartFormFile, MultipartEntity, MultipartFormBody, MultipartFormBody.from summary |
| `http4k-format.model.yml` | 6 | AutoMarshalling asA/stringAsA/asFormatString/convert, Json.parse |
| `http4k-realtime.model.yml` | 6 | WsMessage body, SseMessage Data/Event |
| `http4k-client.model.yml` | 3 | DualSyncAsyncHttpHandler/AsyncHttpHandler SSRF sinks |
| `http4k-template.model.yml` | 2 | TemplatesKt.renderToResponse html-injection sink (+ `$default` variant) |
| `handlebars.model.yml` | 10 | Template.apply sinks (html-injection), Handlebars.compileInline sink (template-injection), Context.combine/Template.apply/compileInline summaries |
| `result4k.model.yml` | 18 | Success/Failure constructors and extractors, ResultKt map/flatMap/recover/peek, NullablesKt valueOrNull/asResultOr |
| `jsoup.model.yml` | 9 | Jsoup.parse/parseBodyFragment + Element.text/html/outerHtml summaries, **Jsoup.clean barrier** (html sanitizer) |
| `jackson.model.yml` | 10 | ObjectMapper.readTree + JsonNode get/path/at/findValue/asText/textValue summaries (CodeQL natively covers readValue, not these) |
| `auth0-jwt.model.yml` | 4 | JWTVerifier.verify, Payload.getClaim, Claim.asString/asList summaries |
| `arrow.model.yml` | 5 | Option.fromNullable/orNull/getOrElse/map, Some.getValue summaries |
| `krouton.model.yml` | 6 | PathElement.parsePathElement, PathTemplate.parse/parsePathElements sources (URL path extraction) |

**Total: 225 model entries** across sources, sinks, summaries, 2 barriers, and 5 neutrals.

**Natively covered (no custom model needed):** `commons-fileupload` (`FileItem`/`FileItemStream`
— CodeQL ≥ 2.24.0) and `FreeMarker` SSTI (`Template.process` / `Configuration.getTemplate` —
Freemarker.qll). Both verified by dedicated test endpoints that fire without any custom model.

## Expected Findings

Source-to-sink taint paths across core vulnerability categories plus a suite of dependency
libraries, totalling **105 CodeQL alerts**, with negative tests asserting barriers and framework
sanitization suppress findings. The full alert set is locked down deterministically — see
Deterministic Testing.

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

### Path Injection (CWE-022) — 4 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| path-01 | pathQuery | `Request.query()` | `ResourceLoader.load()` | Detected |
| path-02 | pathHeader | `Request.header()` | `ResourceLoader.load()` | Detected |
| path-03 | multiFileName | `MultipartFormFile.getFilename()` | `ResourceLoader.load()` | Detected |
| path-04 | pathControlUnsanitized | `Request.query()` | `ResourceLoader.load()` | Detected |

### Dependency & Library Coverage

Beyond http4k itself, libraries commonly used alongside it are modelled (or confirmed natively
covered) so taint does not silently break when request data flows through them.

| Library | File | Paths | Detected | Notes |
|---------|------|-------|----------|-------|
| Jackson `JsonNode` | JacksonRoutes.kt | 8 | 8 | `readTree` + `get/path/at/findValue/findPath/asText/textValue` (CodeQL natively covers `readValue`, not raw `JsonNode`) |
| Jsoup | JsoupControlRoutes.kt | 2 | 2 | `parse → text` / `parseBodyFragment → html`; **`Jsoup.clean` barrier** suppresses the twin (negative test) |
| Auth0 JWT | JwtRoutes.kt | 2 | 2 | `verify → getClaim → asString/asList`. `getClaim` is on `Payload`, not `DecodedJWT` (verified via javap) |
| Arrow `Option` | ArrowRoutes.kt | 3 | 2 | `fromNullable → orNull/getOrElse`; the `map{} → orNull` chain does not propagate (lambda taint) |
| Krouton | KroutonRoutes.kt | 3 | 2 | `parsePathElement` (string + int) as sources; `parse()` extension does not fire (resolves on the `Kt` class) |
| commons-fileupload | CommonsFileUploadRoutes.kt | 4 | 4 | **Native** CodeQL coverage (≥ 2.24.0) — no custom model |
| FreeMarker | FreeMarkerRoutes.kt | 2 | 1 | **Native** SSTI coverage; data-model → writer XSS path not tracked natively |

`ComparisonPlanRoutes.kt` adds 3 model-verification probes (`Uri.toString`, `Uri.copy` receiver
and argument taint) confirming those summaries fire.

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

**105 CodeQL alerts** total, by rule (the exact per-(rule, file) baseline is in
`scripts/expectations.json` and enforced by CI):

| Rule | Alerts |
|------|--------|
| `java/xss` | 73 |
| `java/ssrf` | 10 |
| `java/unvalidated-url-redirection` | 7 |
| `java/sql-injection` | 5 |
| `java/path-injection` | 4 |
| `java/server-side-template-injection` | 3 |
| `java/command-line-injection` | 3 |
| **Total** | **105** |

The `java/xss` count spans core http4k reflection (29), result4k (16), Handlebars (7), the
dependency libraries (Jackson 8, Jsoup 2, JWT 2, Arrow 2, Krouton 2, commons-fileupload 4), and
model-verification probes (3) — including bonus XSS where SSRF/client endpoints echo user input
into the response body.

| Negative test | Expectation | Result |
|---------------|-------------|--------|
| `pathResolvedWithinRoot` | no `java/path-injection` (barrier) | Suppressed ✓ |
| `jsoupClean` | no `java/xss` (Jsoup.clean barrier) | Suppressed ✓ |
| `ResponseSplittingRoutes` / redirects | no `java/http-response-splitting` (framework CR/LF stripping) | Suppressed ✓ |

Both barriers pass: each suppresses its finding while a byte-for-byte-identical control still
alerts. Response-splitting is gone entirely (http4k sanitizes CR/LF internally — those were false
positives, category removed).

**Known non-firing entries** (model kept, documented): `renderToResponse` (CodeQL ViewModel
field-flow), Arrow `map{} → orNull` (lambda taint), Krouton `parse()` (extension resolves on the
`Kt` class), `uriRequestSource`/`miscCurl` (CodeQL receiver-taint limits). FreeMarker's
data-model XSS path is also not natively tracked (SSTI is).

**Log injection:** 3 test endpoints exist (LogInjectionRoutes.kt) but `java/log-injection` is not included in CodeQL's default security query suite. The endpoints validate that http4k sources flow into logging sinks if the query is enabled.

## Deterministic Testing

CodeQL cannot run locally (CI only), and eyeballing scan results — especially the *absence* of a
finding — is not reliable. `scripts/check_findings.py` parses the SARIF output and asserts it
against `scripts/expectations.json`:

It is a **closed-world** check over the whole alert set:

- **`counts`** — exact number of alerts per `(rule, file)`. Every one of the 105 alerts is declared;
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
- Model a method on its **declaring** type — e.g. JWT `getClaim` lives on `Payload`, not the
  `DecodedJWT` subtype that calls it (use `javap` to find the declaring type)
- Two types can share a method name without a subtype relation — krouton `PathElement` and
  `PathElementType` both declare `parsePathElement`; only one matches a given call site
- Some libraries are already covered natively (commons-fileupload ≥ 2.24.0, FreeMarker SSTI) —
  test before writing a redundant model

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
