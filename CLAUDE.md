# http4k CodeQL Custom Models (MaD) Project

Vulnerable test application for validating CodeQL data extension models (Models as Data / MaD
format) for the [http4k](https://http4k.org) Kotlin HTTP toolkit. Each endpoint contains an
intentional vulnerability that should be detected by CodeQL when the custom model YAML files
are applied.

The http4k source code lives in `../http4k/` as a read-only reference for verifying package
names, types, and method signatures. **Do not modify the http4k source.**

## File Organization

Model files go in `.github/codeql/extensions/models/`.

Naming convention: `http4k-<module>.model.yml` for http4k modules, `<library>.model.yml` for
external dependencies.

Current model files (11 files, 186 entries):

**http4k modules:**
1. `http4k-core.model.yml` (104) - Request/Response/Uri/Body/Cookie/Credentials/Parameters sources, sinks, and summaries. Includes form data, cookie extensions, UriKt extensions, parser, curl, UriTemplate, SSRF sinks, response-splitting sinks
2. `http4k-lens.model.yml` (17) - LensExtractor sources, HeaderKt sinks (html-injection, url-redirection), LensInjector.inject sink, Lens/BodyLens/PathLens/LensInjector summaries
3. `http4k-routing.model.yml` (3) - ExtensionsKt.path source, ResourceLoader.load sink, resolvedWithinRoot sanitizer
4. `http4k-filter.model.yml` (1) - ServerFilters.CatchAll stack trace leak summary
5. `http4k-multipart.model.yml` (16) - MultipartFormField, MultipartFormFile, MultipartEntity, MultipartFormBody sources and summaries
6. `http4k-format.model.yml` (6) - AutoMarshalling.asA/stringAsA/asFormatString/convert summaries, Json.parse
7. `http4k-realtime.model.yml` (6) - WsMessage body, SseMessage Data/Event sources
8. `http4k-client.model.yml` (3) - DualSyncAsyncHttpHandler/AsyncHttpHandler SSRF sinks
9. `http4k-template.model.yml` (2) - TemplatesKt.renderToResponse html-injection sink (and its `$default` variant)

**Dependency libraries:**
10. `result4k.model.yml` (18) - dev.forkhandles:result4k Success/Failure/map/flatMap/valueOrNull summaries
11. `handlebars.model.yml` (10) - com.github.jknack:handlebars Template.apply/compileInline sinks and summaries

## CodeQL MaD YAML Format Reference

Pack: `codeql/java-all`

### Extensible Predicates

| Predicate | Columns | Purpose |
|-----------|---------|---------|
| `sourceModel` | 9: package, type, subtypes, name, signature, ext, output, kind, provenance | Tainted data origins |
| `sinkModel` | 9: package, type, subtypes, name, signature, ext, input, kind, provenance | Vulnerable endpoints |
| `summaryModel` | 10: package, type, subtypes, name, signature, ext, input, output, kind, provenance | Flow through methods |
| `neutralModel` | 6: package, type, subtypes, name, signature, provenance | No dataflow impact |
| `barrierModel` | 9: package, type, subtypes, name, signature, ext, kind, input, provenance | Sanitizers blocking taint |
| `barrierGuardModel` | 10: package, type, subtypes, name, signature, ext, kind, input, acceptingValue, provenance | Conditional validators |

### YAML Structure

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: <predicateName>
    data:
      - [<columns...>]
```

### Access Path Syntax

| Token | Meaning |
|-------|---------|
| `Argument[n]` | nth parameter (0-based) |
| `Argument[this]` | Method receiver / qualifier |
| `Argument[n1..n2]` | Parameter range |
| `ReturnValue` | Method return value |
| `Element` | Collection elements |
| `Field[fully.qualified.FieldName]` | Named class field |
| `Parameter[n]` | Callback parameter |
| `MapKey` | Map key |
| `MapValue` | Map value |

Tokens can be chained: `Argument[0].Element`, `ReturnValue.MapValue`

### Kind Values

**Sources:** `remote`, `local`
**Sinks:** `sql-injection`, `command-injection`, `code-injection`, `path-injection`, `url-redirection`, `log-injection`, `request-forgery`, `xpath-injection`, `ldap-injection`, `jndi-injection`, `template-injection`, `html-injection` (used by `java/xss` query — NOT `xss`), `js-injection`, `response-splitting`
**Summaries:** `taint` (approximate), `value` (exact)

### Column Rules

- `package` - fully qualified package (e.g. `"org.http4k.core"`)
- `type` - class/interface name as it appears in JVM bytecode (see Kotlin mapping below)
- `subtypes` - `true`: applies to overrides in subclasses; `false`: exact class only
- `name` - method name in JVM bytecode (properties become `getXxx`)
- `signature` - `""` matches all overloads; `"(String)"` for specific; use fully qualified param types
- `ext` - always `""`
- `provenance` - `"manual"` for hand-written models

## Kotlin-to-JVM Compilation Mapping

CodeQL analyzes JVM bytecode. These mappings are critical for correct model entries.

| Kotlin construct | JVM representation | Example |
|---|---|---|
| Property `val uri: Uri` | Getter `getUri()` | `Request.uri` -> method name `"getUri"` |
| Property `val text: String` | Getter `getText()` | `Body.text` -> method name `"getText"` |
| Extension function `fun Request.form(name: String)` in `FormBody.kt` | Static method on `FormBodyKt.form(Request, String)` | type=`"FormBodyKt"`, receiver is `Argument[0]` |
| Companion object method `Uri.of(value: String)` | Method on `Uri$Companion` or static on `Uri` | type=`"Uri$Companion"`, name=`"of"` |
| `operator fun invoke(target: IN)` | Method literally named `invoke` | name=`"invoke"` |
| `data class Cookie(val name, val value)` | Generates `getName()`, `getValue()`, `component1()`, `copy()` | Use getter names |
| `typealias HttpHandler = (Request) -> Response` | `kotlin.jvm.functions.Function1<Request, Response>` | CodeQL sees the function interface |

**Extension function pattern:** Look at the `.kt` file name, capitalize it, append `Kt`.
The receiver becomes `Argument[0]`, and `subtypes` should be `false` (static method on synthetic class).

**Default parameter pattern:** Methods with default parameters compile to a `$default` variant.
E.g. `fun credentials(charset: Charset = UTF_8)` → JVM method `credentials$default(Uri, Charset, int, Object)`.
Model both the original name and the `$default` variant, or use `""` for method name to match all.

**Companion factory pattern:** `Request(Method, String)` may compile to `Request$Companion.create$default(...)` instead of `invoke`. Check telemetry for actual JVM method names.

## Modelling Design Decisions

### Accessor methods: summaries, not sources

Property accessors like `Uri.getPath()`, `Body.getStream()`, `Cookie.getValue()`, and
`MultipartFormBody.field()` are modelled as **summaries** (taint flows from `Argument[this]`
to `ReturnValue`), not as **sources**.

An alternative approach (used by some other CodeQL model proposals) marks these accessors as
`remote` sources. That makes taint tracking more resilient — if any summary in the chain is
missing, the accessor still introduces taint. However, it also produces false positives:
`Uri.of("https://hardcoded.example.com").getPath()` would be flagged as tainted even though
it contains no user input.

Our summary-based approach requires complete chains (e.g. `Request.getUri()` source →
`Uri.getPath()` summary → sink), but only flags data that actually originates from user input.
The tradeoff is that a missing summary link can silently break taint tracking for a path.

### Sink types: Response, not HttpMessage

Sinks like `body(String)` and `header(String, String)` are modelled on `Response` (with
`subtypes: true`), not on `HttpMessage`. Since `Request` and `Response` are sibling interfaces
under `HttpMessage`, sinking on `Response` avoids false positives where `Request.body()` or
`Request.header()` would be flagged as XSS or response-splitting — those set outgoing request
data, not browser-rendered response data. This eliminates the need for `neutralModel` entries
to suppress Request-side false positives.

### HTTP client SSRF: interfaces, not implementations

Client SSRF sinks are modelled on the interfaces `DualSyncAsyncHttpHandler` and
`AsyncHttpHandler` with `subtypes: true`, rather than listing specific client classes
(OkHttp, JettyClient, etc.) by name. This is future-proof — new client implementations
are automatically covered without model changes.

## http4k Core Types to Model

### Sources (remote)

These methods extract untrusted user input from HTTP requests.

**Source files for verification (in `../http4k/`):**
- `core/core/src/main/kotlin/org/http4k/core/http.kt` - Request, Response, Body, HttpMessage
- `core/core/src/main/kotlin/org/http4k/core/Uri.kt` - Uri data class
- `core/core/src/main/kotlin/org/http4k/core/body/FormBody.kt` - form() extensions
- `core/core/src/main/kotlin/org/http4k/core/cookie/Cookie.kt` - Cookie data class
- `core/core/src/main/kotlin/org/http4k/core/cookie/CookieExtensions.kt` - cookie() extensions
- `core/core/src/main/kotlin/org/http4k/lens/header.kt` - bearerToken(), basicAuthentication() extensions
- `core/core/src/main/kotlin/org/http4k/routing/extensions.kt` - Request.path() extension
- `core/core/src/main/kotlin/org/http4k/core/UriTemplate.kt` - UriTemplate.extract/generate
- `core/core/src/main/kotlin/org/http4k/core/parser.kt` - Request/Response.parse
- `core/core/src/main/kotlin/org/http4k/core/curl.kt` - Request.toCurl
- `core/core/src/main/kotlin/org/http4k/routing/ResourceLoader.kt` - static file loading
- `core/core/src/main/kotlin/org/http4k/routing/resourcePath.kt` - resolvedWithinRoot sanitizer
- `core/core/src/main/kotlin/org/http4k/filter/ServerFilters.kt` - Cors, BasicAuth, CatchAll
- `core/core/src/main/kotlin/org/http4k/filter/ClientFilters.kt` - SetHostFrom, FollowRedirects
- `core/core/src/main/kotlin/org/http4k/filter/RequestFilters.kt` - ProxyHost
- `core/core/src/main/kotlin/org/http4k/client/ext.kt` - DualSyncAsyncHttpHandler, AsyncHttpHandler interfaces
- `core/client/okhttp/src/main/kotlin/org/http4k/client/OkHttp.kt` - OkHttp client
- `core/client/apache/src/main/kotlin/org/http4k/client/ApacheClient.kt` - Apache HTTP client
- `core/client/jetty/src/main/kotlin/org/http4k/client/JettyClient.kt` - Jetty client

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sourceModel
    data:
      # Columns: package, type, subtypes, name, signature, ext, OUTPUT, KIND, provenance
      # --- org.http4k.core.Request (interface) ---
      - ["org.http4k.core", "Request", true, "query", "(String)", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core", "Request", true, "queries", "(String)", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core", "Request", true, "header", "(String)", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core", "Request", true, "headerValues", "(String)", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core", "Request", true, "getBody", "()", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core", "Request", true, "bodyString", "()", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core", "Request", true, "getUri", "()", "", "ReturnValue", "remote", "manual"]

      # --- Extension functions ---
      - ["org.http4k.core.body", "FormBodyKt", false, "form", "", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core.cookie", "CookieExtensionsKt", false, "cookies", "", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.core.cookie", "CookieExtensionsKt", false, "cookie", "", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.routing", "ExtensionsKt", false, "path", "", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.lens", "HeaderKt", false, "bearerToken", "", "", "ReturnValue", "remote", "manual"]
      - ["org.http4k.lens", "HeaderKt", false, "basicAuthentication", "", "", "ReturnValue", "remote", "manual"]
```

### Summaries (taint propagation)

These model how tainted data flows through http4k methods.

**Lens conversion methods (`.int()`, `.long()`, `.map()`, `.boolean()`, `.uuid()`, etc.) do NOT
need separate models.** They are construction-time operations on `LensSpec`/`BiDiLensSpec` that
build new specs. Taint flows at invocation time through `Lens.invoke(target)`, which is modelled
below with `subtypes: true` — covering all lens subtypes regardless of how they were constructed.

**Source files for verification (in `../http4k/`):**
- `core/core/src/main/kotlin/org/http4k/lens/lens.kt` - Lens, BiDiLens
- `core/core/src/main/kotlin/org/http4k/lens/lensSpec.kt` - LensSpec, BiDiLensSpec, conversion extensions
- `core/core/src/main/kotlin/org/http4k/core/Uri.kt` - Uri
- `core/core/src/main/kotlin/org/http4k/core/http.kt` - Body

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: summaryModel
    data:
      # --- Lens extraction: invoke(target) returns extracted value ---
      - ["org.http4k.lens", "Lens", true, "invoke", "", "", "Argument[0]", "ReturnValue", "taint", "manual"]

      # --- Uri property accessors: taint propagates from Uri to components ---
      # Uri is a data class: val path, val query, val host, val scheme, val fragment, val userInfo
      - ["org.http4k.core", "Uri", false, "getPath", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Uri", false, "getQuery", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Uri", false, "getHost", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Uri", false, "getScheme", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Uri", false, "getFragment", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Uri", false, "getUserInfo", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Uri", false, "getAuthority", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]

      # --- Uri.of(String) - factory method on companion object ---
      - ["org.http4k.core", "Uri$Companion", false, "of", "(String)", "", "Argument[0]", "ReturnValue", "taint", "manual"]

      # --- Body property accessors: taint propagates from Body to content ---
      # Body is an interface: val stream, val payload, val text
      - ["org.http4k.core", "Body", true, "getStream", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Body", true, "getPayload", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core", "Body", true, "getText", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]

      # --- Cookie property accessors ---
      # Cookie is a data class: val name, val value
      - ["org.http4k.core.cookie", "Cookie", false, "getValue", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
      - ["org.http4k.core.cookie", "Cookie", false, "getName", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
```

### Sinks

These are points where tainted data can cause vulnerabilities.

**Source files for verification (in `../http4k/`):**
- `core/core/src/main/kotlin/org/http4k/core/http.kt` - Response.header(), Response.body()
- `core/core/src/main/kotlin/org/http4k/lens/header.kt` - Response.html(), Response.location() extensions

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      # Columns: package, type, subtypes, name, signature, ext, INPUT, KIND, provenance
      # --- Response.header(name, value) - url-redirection ---
      - ["org.http4k.core", "Response", true, "header", "(String,String)", "", "Argument[1]", "url-redirection", "manual"]

      # --- Response.body(String) - reflected XSS (kind MUST be "html-injection", NOT "xss") ---
      - ["org.http4k.core", "Response", true, "body", "(String)", "", "Argument[0]", "html-injection", "manual"]
      - ["org.http4k.core", "Response", true, "body", "(Body)", "", "Argument[0]", "html-injection", "manual"]

      # --- Extension functions: header.kt -> HeaderKt ---
      - ["org.http4k.lens", "HeaderKt", false, "html", "", "", "Argument[1]", "html-injection", "manual"]
      - ["org.http4k.lens", "HeaderKt", false, "location", "", "", "Argument[1]", "url-redirection", "manual"]
```

## Verification and Review Checklist

Before accepting any model entry, verify each of these:

1. **Package name** - Open the `.kt` source file (in `../http4k/`) and check the `package` declaration matches exactly
2. **Type name (JVM)** - Account for Kotlin compilation:
   - Interfaces/classes: use the name as-is (e.g. `Request`, `Uri`, `Body`)
   - Extension function files: `<FileName>Kt` (e.g. `FormBodyKt`, `CookieExtensionsKt`)
   - Companion objects: `<Class>$Companion` (e.g. `Uri$Companion`)
3. **Method name (JVM)** - Properties become `get<Name>`; `invoke` operator stays `invoke`
4. **Subtypes flag** - `true` for interfaces (`Request`, `Response`, `HttpMessage`, `Body`) and open classes; `false` for `data class`, `object`, companion objects, and `<File>Kt` synthetic classes
5. **Signature** - Use `""` to match all overloads initially; refine with specific types only when disambiguation is needed
6. **Access paths** - `ReturnValue` for data extraction; `Argument[0]` for first param (or receiver in extension functions); `Argument[this]` for instance method receivers
7. **Source file cross-reference** - Always verify against the actual source before writing a model entry

### Key Source Files for Cross-Reference (in `../http4k/`)

```
core/core/src/main/kotlin/org/http4k/core/http.kt          # Request, Response, Body, HttpMessage
core/core/src/main/kotlin/org/http4k/core/Uri.kt            # Uri data class + companion
core/core/src/main/kotlin/org/http4k/core/Parameters.kt     # Parameters, Uri.queries()
core/core/src/main/kotlin/org/http4k/core/body/FormBody.kt  # form() extension functions
core/core/src/main/kotlin/org/http4k/core/cookie/Cookie.kt  # Cookie data class
core/core/src/main/kotlin/org/http4k/core/cookie/CookieExtensions.kt  # cookie() extensions
core/core/src/main/kotlin/org/http4k/lens/lens.kt           # Lens, BiDiLens
core/core/src/main/kotlin/org/http4k/lens/lensSpec.kt       # LensSpec, BiDiLensSpec, conversion extensions
core/core/src/main/kotlin/org/http4k/lens/query.kt          # Query lens
core/core/src/main/kotlin/org/http4k/lens/header.kt         # Header lens + bearerToken, basicAuth, html, location
core/core/src/main/kotlin/org/http4k/lens/path.kt           # Path lens
core/core/src/main/kotlin/org/http4k/lens/Cookies.kt        # Cookies lens
core/core/src/main/kotlin/org/http4k/lens/webForm.kt        # FormField, WebForm
core/core/src/main/kotlin/org/http4k/lens/body.kt           # BodyLens, BiDiBodyLens
core/core/src/main/kotlin/org/http4k/routing/extensions.kt  # Request.path() extension
core/core/src/main/kotlin/org/http4k/core/Parameters.kt     # toParameters, findSingle, queries
core/multipart/src/main/kotlin/org/http4k/core/MultipartFormBody.kt  # MultipartFormBody, MultipartEntity
core/multipart/src/main/kotlin/org/http4k/lens/parts.kt     # MultipartFormField, MultipartFormFile
core/format/core/src/main/kotlin/org/http4k/format/AutoMarshalling.kt  # asA, asFormatString
core/realtime-core/src/main/kotlin/org/http4k/websocket/WsMessage.kt  # WebSocket messages
core/realtime-core/src/main/kotlin/org/http4k/sse/SseMessage.kt       # SSE messages
```

API documentation for discovering additional APIs: https://www.http4k.org/api/http4k-core/index.html

## Testing Models

CodeQL analysis runs in GitHub Actions (`.github/workflows/codeql.yml`) on every push to `main`.
Model files in `.github/codeql/extensions/models/` are auto-discovered.

Every new model entry that adds a detectable source-to-sink path needs a corresponding
vulnerable test endpoint in `src/main/kotlin/com/example/vulnerable/routes/`. If CodeQL
doesn't detect the endpoint, investigate the model entry.

### Key CodeQL Behaviours

- Kotlin nullable safe call `?.` can break taint tracking — use `if` checks instead
- Multiple source flows to a shared sink helper produce a single CodeQL alert — inline queries for independent detection
- CodeQL can't track taint through user-defined data class getters (e.g., `asA<UserInput>().name`) — use modelled APIs instead
- `java/log-injection` is NOT in CodeQL's default security suite
- `java/js-injection` is NOT in CodeQL's default security suite — adding `js-injection` kind would duplicate `java/xss` alerts
- Line number shifts from import changes can cause CodeQL to close and re-create alerts (not a real loss)

## Dependency Models

Beyond http4k's own API surface, we model key libraries that http4k depends on or that are
commonly used alongside it. Without these, taint can silently break when data passes through
unmodelled library calls.

Current dependency model files:

- `result4k.model.yml` — `dev.forkhandles:result4k` (18 summaries). Functional Result type used
  in http4k core (oauth, lambda). Wrapping tainted data in `Success(input)` and unwrapping via
  `.value`, `.map {}`, `.valueOrNull()` breaks taint without these summaries.
- `handlebars.model.yml` — `com.github.jknack:handlebars` (10 entries). Template engine wrapped
  by `http4k-template-handlebars`. `Template.apply` is an `html-injection` sink (XSS via context
  data), `Handlebars.compileInline` is a `template-injection` sink (SSTI via user-controlled
  template string).
- `http4k-template.model.yml` — `org.http4k.template` (2 summaries). The http4k template
  abstraction layer: `TemplatesKt.renderToResponse` propagates taint from ViewModel to Response.

**Klaxon** (`com.beust.klaxon`) does NOT need a separate model file — `ConfigurableKlaxon`
extends `AutoMarshalling`, which is already modelled in `http4k-format.model.yml` with
`subtypes: true`.

### Known precision tradeoffs in dependency models

- **`Template.apply` (Handlebars) is modelled as an unconditional `html-injection` sink**, but
  Handlebars auto-escapes `{{x}}` by default — only `{{{x}}}` (triple-stache) and `SafeString`
  bypass escaping. In real-world apps this produces false positives on safe escaped templates.
  Accepted here because the test app's purpose is detection coverage, and our test endpoint uses
  genuinely-unsafe `{{{this}}}`. A more precise model would only flag SafeString/triple-stache,
  which MaD cannot express.
- **Every model entry has a dedicated test endpoint.** Each result4k entry (Success/Failure
  constructors, component1, asSuccess/asFailure, map/flatMap/mapFailure/flatMapFailure,
  recover/onFailure/peek/peekFailure, valueOrNull/asResultOr) and each handlebars entry
  (Template.apply overloads, compileInline overloads, Context.combine variants) is exercised by
  its own endpoint with an **inline** `Response.body` sink — a shared sink helper would
  consolidate multiple flows into a single alert, hiding per-entry validation.
- **`renderToResponse` sink relies on ViewModel field flow.** The http4k-template sink fires only
  if CodeQL propagates taint from a tainted constructor argument through the ViewModel object to
  the `renderToResponse` call. This is the least certain entry to validate; if CI does not flag
  `templateRenderToResponse`, the limitation is the field-flow tracking, not the model signature.

### When to add a new dependency model

Add a model file for a library when:
1. It is a declared dependency of http4k (check `../http4k/gradle/libs.versions.toml`)
2. Tainted data passes through its APIs (wrappers, transformers, renderers)
3. Without the model, CodeQL taint tracking breaks in the chain

Do NOT model libraries that are:
- Already covered by subtypes (e.g., Klaxon via AutoMarshalling)
- Not http4k dependencies (e.g., krouton — third-party routing add-on, not in http4k's deps)
- Application-specific internal libraries (e.g., OPA's anura-common)

## Discovering Dependencies from Real-World Repos

To improve model coverage, scan real-world http4k applications for libraries used alongside
http4k where taint tracking could break. This is a two-phase process using different models
to optimise token usage.

### Phase 1: Discovery (use Haiku)

Haiku is sufficient for this phase — the work is pattern matching and listing, not reasoning
about taint semantics or MaD format.

**Goal:** Identify libraries used alongside http4k that could carry tainted data.

**How to search for real repos:**

```bash
# Search GitHub for repos using http4k (build files mentioning http4k dependency)
gh search repos --language=Kotlin "http4k" --sort=stars --limit=20

# Or search for code patterns in build files
gh search code "http4k-core" --filename=build.gradle.kts --limit=50
gh search code "http4k-core" --filename=build.gradle --limit=50
gh search code "http4k-core" --filename=pom.xml --limit=50
```

**What to extract from each repo:**

1. **Dependencies** — scan `build.gradle.kts`, `build.gradle`, `pom.xml`, or
   `gradle/libs.versions.toml` for all non-test dependencies
2. **Import patterns** — grep for import statements to find which libraries handle data
   that also passes through http4k:
   ```bash
   # In the target repo, find imports that aren't http4k, kotlin stdlib, or java stdlib
   grep -rh "^import " src/main/kotlin/ | sort -u | grep -v "org.http4k\|kotlin\.\|java\.\|javax\."
   ```
3. **Data flow patterns** — look for code where http4k request data is passed into
   third-party library calls:
   ```bash
   # Find functions that take Request and use non-http4k libraries
   grep -l "import org.http4k.core.Request" src/main/kotlin/**/*.kt | \
     xargs grep -l "import com\.\|import io\.\|import dev\."
   ```

**Output format for discovery:** A simple table:

| Library | Package | Used with http4k? | Taint-relevant APIs | Priority |
|---------|---------|-------------------|---------------------|----------|
| result4k | dev.forkhandles.result4k | Yes (wraps request data) | Success, map, valueOrNull | High |
| arrow-core | arrow.core | Maybe (Either/Option wrappers) | Either.fold, Option.getOrNull | Medium |
| exposed | org.jetbrains.exposed | Yes (SQL from request params) | Already built-in CodeQL sinks | Skip |

### Phase 2: Modelling (use Sonnet)

Sonnet is needed for this phase — it requires understanding MaD column semantics,
Kotlin-to-JVM compilation rules, and taint propagation logic.

**For each high-priority library from Phase 1:**

1. **Locate the source** — check if it's in `../http4k/` (http4k dependency) or needs
   external reference. Use Maven Central or GitHub to find the API.
2. **Identify taint-relevant methods** — constructors that wrap data, accessors that extract
   it, transformers that pass it through, and any methods that could be sinks.
3. **Write the model file** — follow the naming convention: `<library-name>.model.yml` for
   external libraries, `http4k-<module>.model.yml` for http4k modules.
4. **Create test endpoints** — add the library as a dependency in `build.gradle.kts` and
   create vulnerable routes exercising each modelled path.
5. **Verify with CI** — push, check CodeQL alerts, update README and counts.

**Verification questions for each candidate library:**
- Does tainted data actually flow through this library's APIs? (Not just "is it imported")
- Would CodeQL lose taint tracking without a model? (Check if it's a wrapper/transformer)
- Is it already covered by an existing model with `subtypes: true`?
- Is it a published library with stable APIs, or an internal/abandoned project?

### Libraries already assessed

| Library | Package | Status | Reason |
|---------|---------|--------|--------|
| result4k | `dev.forkhandles.result4k` | **Modelled** | http4k dependency, wraps tainted data in Result type |
| handlebars | `com.github.jknack.handlebars` | **Modelled** | http4k template engine, renders user data to HTML |
| klaxon | `com.beust.klaxon` | **Covered** | Extends AutoMarshalling (subtypes=true in http4k-format) |
| krouton | `com.natpryce.krouton` | **Skipped** | Not an http4k dependency, abandoned (last release 2020) |

## Development Workflow

1. **Pick an API to model** - start with the priority list in File Organization
2. **Read the source** - open the `.kt` file in `../http4k/`, verify package, type, method name, and signature
3. **Apply Kotlin-to-JVM mapping** - translate to the JVM representation CodeQL will see
4. **Write the YAML entry** - follow the MaD format, use `""` for signature initially
5. **Add a test endpoint** - create a vulnerable route exercising the new model entry
6. **Cross-reference** - re-check against the verification checklist
7. **Push and verify** - push to trigger CI, check CodeQL alerts match expectations
8. **Iterate** - refine signatures, add summaries for missed flow steps
