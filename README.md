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
  codeql/extensions/          # 9 custom MaD model YAML files
  workflows/codeql.yml        # CodeQL CI workflow (build-mode: manual)
src/main/kotlin/com/example/vulnerable/
  App.kt                      # Route registration (~50 endpoints)
  model/UserInput.kt          # Data class for JSON deserialization tests
  routes/
    XssRoutes.kt              # 10 endpoints - reflected XSS
    RedirectRoutes.kt         #  5 endpoints - open redirect
    SsrfRoutes.kt             #  6 endpoints - server-side request forgery
    PathInjectionRoutes.kt    #  2 endpoints - path traversal
    SqlInjectionRoutes.kt     #  7 endpoints - SQL injection
    CommandInjectionRoutes.kt #  3 endpoints - command injection
    MultipartRoutes.kt        #  2 endpoints - multipart source coverage
    LensRoutes.kt             #  3 endpoints - lens extraction chains
    HeaderRoutes.kt           #  2 endpoints - auth header sources
    UriRoutes.kt              #  2 endpoints - URI/RequestSource sources
    MiscRoutes.kt             #  4 endpoints - parse, curl, params, JSON
expected-findings.json        # Machine-readable expected findings
```

## Custom Model Files

All 9 model files live in `.github/codeql/extensions/` and are auto-discovered by CodeQL:

| File | Type | Entries | Coverage |
|------|------|---------|----------|
| `http4k-core-sources.model.yml` | sourceModel | 25 | Request query/header/body/uri, form data, cookies, path params, auth headers |
| `http4k-core-summaries.model.yml` | summaryModel | 62 | Uri accessors/mutation, Body accessors, Cookie getters, HttpMessage mutation, parsing, curl |
| `http4k-core-sinks.model.yml` | sinkModel | 11 | Response body/header injection, html(), location(), ResourceLoader.load, Request.uri, UriTemplate |
| `http4k-lens-summaries.model.yml` | summaryModel | 7 | Lens/BodyLens/PathLens/LensExtractor/LensInjector invoke/extract/inject |
| `http4k-multipart-sources.model.yml` | sourceModel | 15 | MultipartFormField, MultipartFormFile, MultipartEntity, MultipartFormBody |
| `http4k-format-summaries.model.yml` | summaryModel | 4 | AutoMarshalling asA/asInputStream/asFormatString/convert |
| `http4k-realtime-sources.model.yml` | sourceModel | 6 | WsMessage body, SseMessage Data/Event |
| `http4k-ssrf-sinks.model.yml` | sinkModel | 5 | Uri extend/relative/appendToPath, Request factory, Request.uri(Uri) |
| `http4k-filter-models.model.yml` | barrierModel + summaryModel | 2 | resolvedWithinRoot sanitizer, CatchAll stack trace leak |

**Total: 137 model entries.**

## Expected Findings

46 distinct source-to-sink taint paths across 6 vulnerability categories:

### XSS (CWE-079) — 21 paths

| ID | Function | Source | Intermediaries | Sink | Confidence |
|----|----------|--------|----------------|------|------------|
| xss-01 | xssQueryBody | `Request.query()` | — | `Response.body(String)` | High |
| xss-02 | xssBodyStringBody | `Request.bodyString()` | — | `Response.body(String)` | High |
| xss-03 | xssBodyReflect | `Request.bodyString()` | — | `Response.body(String)` | High |
| xss-04 | xssHeaderHtml | `Request.header()` | — | `HeaderKt.html()` | High |
| xss-05 | xssFormBody | `FormBodyKt.form()` | — | `Response.body(String)` | High |
| xss-06 | xssBodyObject | `Request.getBody()` | stream, reader, readText | `Response.body(String)` | Medium |
| xss-07 | xssBodyStream | `Request.getBody()` | payload, Body() | `Response.body(Body)` | Medium |
| xss-08 | xssQueriesBody | `Request.queries()` | joinToString | `Response.body(String)` | Medium |
| xss-09 | xssHeaderValuesBody | `Request.headerValues()` | joinToString | `Response.body(String)` | Medium |
| xss-10 | xssGetHeadersBody | `HttpMessage.getHeaders()` | joinToString | `Response.body(String)` | Medium |
| xss-11 | authBasicXss | `HeaderKt.basicAuthentication()` | Credentials.user | `Response.body(String)` | Low |
| xss-12 | uriCredentials | `Uri.credentials()` | Credentials fields | `Response.body(String)` | Low |
| xss-13 | uriRequestSource | `RequestSource.getAddress()` | — | `Response.body(String)` | Medium |
| xss-14 | lensQueryExtract | `Lens.invoke(Request)` | — | `Response.body(String)` | Medium |
| xss-15 | lensBodyExtract | `BodyLens.invoke(Request)` | — | `Response.body(String)` | Medium |
| xss-16 | lensExtractorGet | `LensExtractor.extract()` | — | `Response.body(String)` | Medium |
| xss-17 | multiFieldXss | `MultipartFormField.getValue()` | lens chain | `Response.body(String)` | Low |
| xss-18 | miscParse | `Request.bodyString()` | Request.parse, bodyString | `Response.body(String)` | Low |
| xss-19 | miscCurl | Request (tainted) | toCurl() | `Response.body(String)` | Low |
| xss-20 | miscParams | `Request.getUri()` | query, toParameters, findSingle | `Response.body(String)` | Low |
| xss-21 | miscJsonConvert | `Request.bodyString()` | Jackson.parse, asFormatString | `Response.body(String)` | Low |

### URL Redirect (CWE-601) — 5 paths

| ID | Function | Source | Intermediaries | Sink | Confidence |
|----|----------|--------|----------------|------|------------|
| redirect-01 | redirectHeader | `Request.query()` | — | `Response.header(Location)` | High |
| redirect-02 | redirectReplace | `Request.query()` | — | `Response.replaceHeader(Location)` | High |
| redirect-03 | redirectLocation | `Request.query()` | Uri.of() | `HeaderKt.location()` | Medium |
| redirect-04 | redirectTemplate | `Request.query()` | UriTemplate.generate() | `Response.header(Location)` | Low |
| redirect-05 | redirectCookieSrc | `CookieExtensionsKt.cookie()` | Cookie.getValue() | `Response.header(Location)` | Medium |

### SSRF / Request Forgery (CWE-918) — 6 paths

| ID | Function | Source | Intermediaries | Sink | Confidence |
|----|----------|--------|----------------|------|------------|
| ssrf-01 | ssrfUriSet | `Request.query()` | Uri.of() | `Request.uri(Uri)` | Medium |
| ssrf-02 | ssrfRequestCreate | `Request.query()` | — | `Request(Method, String)` | High |
| ssrf-03 | ssrfExtend | `Request.query()` | Uri.of() | `Uri.extend(Uri)` | Medium |
| ssrf-04 | ssrfRelative | `Request.query()` | — | `Uri.relative(String)` | Medium |
| ssrf-05 | ssrfAppendPath | `Request.query()` | — | `Uri.appendToPath(String)` | Medium |
| ssrf-06 | ssrfHeaderUrl | `Request.header()` | Uri.host() | `Request.uri(Uri)` | Medium |

### SQL Injection (CWE-089) — 8 paths

| ID | Function | Source | Intermediaries | Sink (built-in) | Confidence |
|----|----------|--------|----------------|------|------------|
| sqli-01 | sqlQuery | `Request.query()` | — | `Statement.executeQuery()` | High |
| sqli-02 | sqlForm | `FormBodyKt.form()` | — | `Statement.executeQuery()` | High |
| sqli-03 | sqlFormMap | `FormBodyKt.formAsMap()` | Map.get, firstOrNull | `Statement.executeQuery()` | Medium |
| sqli-04 | sqlHeader | `Request.header()` | — | `Statement.executeQuery()` | High |
| sqli-05 | sqlCookie | `CookieExtensionsKt.cookie()` | Cookie.getValue() | `Statement.executeQuery()` | Medium |
| sqli-06 | sqlBearer | `HeaderKt.bearerToken()` | — | `Statement.executeQuery()` | Medium |
| sqli-07 | sqlJson | `Request.bodyString()` | asA(), getName() | `Statement.executeQuery()` | Low |
| sqli-08 | authBearerSql | `HeaderKt.bearerToken()` | — | `Statement.executeQuery()` | Medium |

### Command Injection (CWE-078) — 3 paths

| ID | Function | Source | Intermediaries | Sink (built-in) | Confidence |
|----|----------|--------|----------------|------|------------|
| cmdi-01 | cmdQuery | `Request.query()` | — | `Runtime.exec()` | High |
| cmdi-02 | cmdHeader | `Request.header()` | — | `Runtime.exec()` | High |
| cmdi-03 | cmdBody | `Request.bodyString()` | — | `Runtime.exec()` | High |

### Path Injection (CWE-022) — 3 paths

| ID | Function | Source | Intermediaries | Sink | Confidence |
|----|----------|--------|----------------|------|------------|
| path-01 | pathQuery | `Request.query()` | — | `ResourceLoader.load()` | High |
| path-02 | pathHeader | `Request.header()` | — | `ResourceLoader.load()` | High |
| path-03 | multiFileName | `MultipartFormFile.getFilename()` | lens chain | `ResourceLoader.load()` | Low |

### Detection Estimates

| Confidence | Count | Description |
|------------|-------|-------------|
| High | 16 | Direct source-to-sink, 0-1 intermediary steps |
| Medium | 18 | 1-2 intermediaries with modelled summaries |
| Low | 12 | Complex chains (3+ steps), unmodelled intermediaries, or multipart lens chains |

| Scenario | Expected Findings |
|----------|-------------------|
| Conservative (high confidence only) | 14–20 |
| Realistic (first run) | 20–30 |
| Optimistic (all models work) | 35–46 |

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

### Analyzing Gaps

- **True Positives:** Expected findings that appear — models are working
- **False Negatives:** Expected findings missing — model entry or test code needs adjustment
- **Unexpected:** Extra findings — bonus coverage or over-broad models

Common reasons for false negatives:
- Source/sink type name doesn't match JVM bytecode (Kotlin-to-JVM mapping issue)
- Missing summary model for an intermediate step (taint is lost mid-chain)
- CodeQL's analysis depth limit exceeded (too many intermediary steps)
- Signature mismatch (model specifies a signature that doesn't match the overload used)
