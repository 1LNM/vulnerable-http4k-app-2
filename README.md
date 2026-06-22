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
  codeql/extensions/models/     # 10 custom MaD model YAML files
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
    LensRoutes.kt               #  3 endpoints - lens extraction chains
    HeaderRoutes.kt             #  2 endpoints - auth header sources
    UriRoutes.kt                #  2 endpoints - URI/RequestSource sources
    MiscRoutes.kt               #  4 endpoints - parse, curl, params, JSON
    ClientSsrfRoutes.kt         #  4 endpoints - HTTP client SSRF
    LogInjectionRoutes.kt       #  3 endpoints - log injection
```

## Custom Model Files

All 10 model files live in `.github/codeql/extensions/models/` and are auto-discovered by CodeQL:

| File | Type | Entries | Coverage |
|------|------|---------|----------|
| `http4k-core-sources.model.yml` | sourceModel | 26 | Request query/header/body/uri, form data, cookies, path params, auth headers, Uri.credentials |
| `http4k-core-summaries.model.yml` | summaryModel | 67 | Uri accessors/mutation (incl. UriKt extensions), Body/Cookie/Credentials accessors, HttpMessage mutation, parsing, curl, Request.getSource |
| `http4k-core-sinks.model.yml` | sinkModel | 11 | Response body (html-injection)/header injection, html(), location(), ResourceLoader.load, Request.uri, UriTemplate |
| `http4k-lens-summaries.model.yml` | sourceModel + summaryModel | 9 | LensExtractor.invoke/extract as remote sources; Lens/BodyLens/PathLens/LensInjector taint summaries |
| `http4k-multipart-sources.model.yml` | sourceModel | 15 | MultipartFormField, MultipartFormFile, MultipartEntity, MultipartFormBody |
| `http4k-format-summaries.model.yml` | summaryModel | 6 | AutoMarshalling asA/stringAsA/asInputStream/asFormatString/convert, Json.parse |
| `http4k-realtime-sources.model.yml` | sourceModel | 6 | WsMessage body, SseMessage Data/Event |
| `http4k-ssrf-sinks.model.yml` | sinkModel | 5 | UriKt.extend/relative/appendToPath, Request$Companion.create$default, Request.uri(Uri) |
| `http4k-filter-models.model.yml` | barrierModel + summaryModel | 2 | resolvedWithinRoot sanitizer, CatchAll stack trace leak |
| `http4k-client-models.model.yml` | sinkModel + summaryModel | 3 | DualSyncAsyncHttpHandler/AsyncHttpHandler invoke as SSRF execution sinks |

**Total: 150 model entries.**

## Expected Findings

51 distinct source-to-sink taint paths across 7 vulnerability categories.

### XSS (CWE-079) — 19 paths

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
| xss-14 | lensQueryExtract | `LensExtractor.invoke()` | `Response.body(String)` | Pending |
| xss-15 | lensBodyExtract | `LensExtractor.invoke()` | `Response.body(String)` | Pending |
| xss-16 | lensExtractorGet | `LensExtractor.extract()` | `Response.body(String)` | Pending |
| xss-17 | multiFieldXss | `MultipartFormField.getValue()` | `Response.body(String)` | Detected |
| xss-18 | miscParse | `Request.bodyString()` | `Response.body(String)` | Detected |
| xss-20 | miscParams | `Request.getUri()` | `Response.body(String)` | Detected |
| xss-21 | miscJsonConvert | `Request.bodyString()` | `Response.body(String)` | Detected |

**Excluded from count:**
- xss-13 (uriRequestSource): `RequestSource` is modelled as `local` source, not `remote` — CodeQL correctly does not flag it as XSS
- xss-19 (miscCurl): Requires the `Request` object itself to carry taint, which CodeQL doesn't support (only method return values are tainted)

### URL Redirect (CWE-601) — 5 paths

| ID | Function | Source | Sink | Status |
|----|----------|--------|------|--------|
| redirect-01 | redirectHeader | `Request.query()` | `Response.header(Location)` | Detected |
| redirect-02 | redirectReplace | `Request.query()` | `Response.replaceHeader(Location)` | Detected |
| redirect-03 | redirectLocation | `Request.query()` | `HeaderKt.location()` | Detected |
| redirect-04 | redirectTemplate | `Request.query()` | `Response.header(Location)` | Detected |
| redirect-05 | redirectCookieSrc | `CookieExtensionsKt.cookie()` | `Response.header(Location)` | Detected |

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
| client-01 | ssrfOkHttp | `Request.query()` | `DualSyncAsyncHttpHandler.invoke(Request)` | Pending |
| client-02 | ssrfJettyClient | `Request.header()` | `DualSyncAsyncHttpHandler.invoke(Request)` | Pending |
| client-03 | ssrfOkHttpUri | `Request.query()` | `DualSyncAsyncHttpHandler.invoke(Request)` | Pending |
| client-04 | ssrfOkHttpAsync | `Request.query()` | `AsyncHttpHandler.invoke(Request, callback)` | Pending |

### Log Injection (CWE-117) — 3 paths

| ID | Function | Source | Sink (built-in) | Status |
|----|----------|--------|------|--------|
| log-01 | logQuery | `Request.query()` | `Logger.info()` | Pending |
| log-02 | logHeader | `Request.header()` | `Logger.warning()` | Pending |
| log-03 | logForm | `FormBodyKt.form()` | `Logger.info()` | Pending |

### SQL Injection (CWE-089) — 8 paths

| ID | Function | Source | Sink (built-in) | Status |
|----|----------|--------|------|--------|
| sqli-01 | sqlQuery | `Request.query()` | `Statement.executeQuery()` | Detected |
| sqli-02 | sqlForm | `FormBodyKt.form()` | `Statement.executeQuery()` | Detected |
| sqli-03 | sqlFormMap | `FormBodyKt.formAsMap()` | `Statement.executeQuery()` | Detected |
| sqli-04 | sqlHeader | `Request.header()` | `Statement.executeQuery()` | Detected |
| sqli-05 | sqlCookie | `CookieExtensionsKt.cookie()` | `Statement.executeQuery()` | Not detected |
| sqli-06 | sqlBearer | `HeaderKt.bearerToken()` | `Statement.executeQuery()` | Not detected |
| sqli-07 | sqlJson | `Request.bodyString()` | `Statement.executeQuery()` | Not detected |
| sqli-08 | authBearerSql | `HeaderKt.bearerToken()` | `Statement.executeQuery()` | Detected |

**Note:** CodeQL consolidates SQL injection alerts per sink location. All `sql*` functions share one `executeQuery()` call at SqlInjectionRoutes.kt:28, so multiple source flows appear as a single alert with multiple paths.

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

| Category | Expected | Detected | Pending | Not Detected |
|----------|----------|----------|---------|--------------|
| XSS | 19 | 19 | 0 | 0 |
| Redirect | 5 | 5 | 0 | 0 |
| SSRF | 6 | 6 | 0 | 0 |
| Client SSRF | 4 | 3 | 0 | 1 |
| Log Injection | 3 | 0 | 3 (new) | 0 |
| SQL Injection | 8 | 5 | 0 | 3 |
| Command Injection | 3 | 3 | 0 | 0 |
| Path Injection | 3 | 3 | 0 | 0 |
| **Total** | **51** | **44** | **3** | **4** |

**Bonus findings:** CodeQL also detects ~7 secondary XSS alerts from SSRF endpoints that echo user input back in the response body. These are true positives not listed above.

**Last CI run:** 43 distinct CodeQL alerts (includes bonus findings and consolidated SQL alerts).

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
