# Vulnerable http4k Test App

Test application for validating [CodeQL MaD (Models as Data)](https://codeql.github.com/) custom models for the [http4k](https://http4k.org) Kotlin HTTP toolkit. Every endpoint contains an intentional vulnerability that should be detected by CodeQL when the custom model YAML files are applied.

## Stack

- Kotlin 2.2.0 (must stay below 2.3.30 for CodeQL compatibility)
- http4k 6.53.0.0
- JDK 21, Gradle 8.12
- H2 in-memory database (for SQL injection endpoints)

## Project Structure

```
.github/
  codeql/extensions/models/     # 8 custom MaD model YAML files (by module)
  workflows/codeql.yml          # CodeQL CI workflow (build-mode: manual)
src/main/kotlin/com/example/vulnerable/
  App.kt                        # Route registration (~50 endpoints)
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
    ResponseSplittingRoutes.kt  #  2 endpoints - HTTP response splitting
```

## Custom Model Files

All 8 model files live in `.github/codeql/extensions/models/`, organized by http4k module:

| File | Entries | Coverage |
|------|---------|----------|
| `http4k-core.model.yml` | 104 | Request/Response/Uri/Body/Cookie/Credentials sources, sinks, summaries. Form data, cookie extensions, UriKt extensions, parser, curl, UriTemplate, SSRF sinks, response-splitting sinks, Uri.toString/copy summaries |
| `http4k-lens.model.yml` | 17 | LensExtractor sources, HeaderKt sinks (html-injection, url-redirection), LensInjector.inject sink, Lens/BodyLens/PathLens/LensInjector summaries |
| `http4k-routing.model.yml` | 3 | ExtensionsKt.path source, ResourceLoader.load sink, resolvedWithinRoot sanitizer |
| `http4k-filter.model.yml` | 1 | ServerFilters.CatchAll stack trace leak |
| `http4k-multipart.model.yml` | 16 | MultipartFormField, MultipartFormFile, MultipartEntity, MultipartFormBody, MultipartFormBody.from summary |
| `http4k-format.model.yml` | 6 | AutoMarshalling asA/stringAsA/asFormatString/convert, Json.parse |
| `http4k-realtime.model.yml` | 6 | WsMessage body, SseMessage Data/Event |
| `http4k-client.model.yml` | 3 | DualSyncAsyncHttpHandler/AsyncHttpHandler SSRF sinks |

**Total: 156 model entries.**

## Expected Findings

52 distinct source-to-sink taint paths across 8 vulnerability categories.

### XSS (CWE-079) — 20 paths

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
- xss-19 (miscCurl): Requires the `Request` object itself to carry taint, which CodeQL doesn't support (only method return values are tainted)

### URL Redirect (CWE-601) — 6 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| redirect-01 | redirectHeader | `Request.query()` | `Response.header(Location)` | Detected |
| redirect-02 | redirectReplace | `Request.query()` | `Response.replaceHeader(Location)` | Detected |
| redirect-03 | redirectLocation | `Request.query()` | `HeaderKt.location()` | Detected |
| redirect-04 | redirectTemplate | `Request.query()` | `Response.header(Location)` | Detected |
| redirect-05 | redirectCookieSrc | `CookieExtensionsKt.cookie()` | `Response.header(Location)` | Detected |
| redirect-06 | splitHeaderValue | `Request.query()` | `Response.header(name, tainted)` | Detected |

### HTTP Response Splitting (CWE-113) — 2 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| split-01 | splitHeaderName | `Request.query()` | `Response.header(tainted, value)` | Detected |
| split-02 | splitHeaderValue | `Request.query()` | `Response.header(name, tainted)` | Detected |

**Bonus findings:** CodeQL also detects response-splitting on 3 existing redirect endpoints (redirectHeader, redirectTemplate, redirectCookieSrc) since `Response.header` value is now also a response-splitting sink.

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

### Summary

| Category | Expected | Detected |
|----------|----------|----------|
| XSS | 20 | 20 |
| Redirect | 6 | 6 |
| Response Splitting | 2 | 2 |
| SSRF | 6 | 6 |
| Client SSRF | 4 | 4 |
| SQL Injection | 8 | 8 |
| Command Injection | 3 | 3 |
| Path Injection | 3 | 3 |
| **Total** | **52** | **52** |

**100% detection rate** on all expected source-to-sink paths.

**Bonus findings:** CodeQL also detects secondary alerts from SSRF/client endpoints that echo user input in the response body (XSS), and from redirect endpoints that also match response-splitting. These are true positives not listed above.

**Log injection:** 3 test endpoints exist (LogInjectionRoutes.kt) but `java/log-injection` is not included in CodeQL's default security query suite. The endpoints validate that http4k sources flow into logging sinks if the query is enabled.

**Last CI run:** 60 distinct CodeQL alerts (includes bonus findings and consolidated SQL alerts).

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
6. Uploads SARIF as a downloadable artifact

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
