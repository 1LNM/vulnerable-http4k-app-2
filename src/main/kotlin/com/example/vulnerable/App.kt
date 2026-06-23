package com.example.vulnerable

import org.http4k.core.Method.*
import org.http4k.routing.bind
import org.http4k.routing.routes
import org.http4k.server.Netty
import org.http4k.server.asServer
import com.example.vulnerable.routes.*

fun main() {
    val app = routes(
        // XSS
        "/xss/query-body" bind GET to ::xssQueryBody,
        "/xss/body-reflect" bind POST to ::xssBodyReflect,
        "/xss/header-html" bind GET to ::xssHeaderHtml,
        "/xss/form-body" bind POST to ::xssFormBody,
        "/xss/body-object" bind POST to ::xssBodyObject,
        "/xss/body-stream" bind POST to ::xssBodyStream,
        "/xss/queries-body" bind GET to ::xssQueriesBody,
        "/xss/headerValues-body" bind GET to ::xssHeaderValuesBody,
        "/xss/getHeaders-body" bind GET to ::xssGetHeadersBody,
        "/xss/bodyString-body" bind POST to ::xssBodyStringBody,

        // Open Redirect
        "/redirect/header" bind GET to ::redirectHeader,
        "/redirect/replace" bind GET to ::redirectReplace,
        "/redirect/location" bind GET to ::redirectLocation,
        "/redirect/template" bind GET to ::redirectTemplate,
        "/redirect/cookie-src" bind GET to ::redirectCookieSrc,

        // SSRF
        "/ssrf/uri-set" bind GET to ::ssrfUriSet,
        "/ssrf/request-create" bind GET to ::ssrfRequestCreate,
        "/ssrf/extend" bind GET to ::ssrfExtend,
        "/ssrf/relative" bind GET to ::ssrfRelative,
        "/ssrf/append-path" bind GET to ::ssrfAppendPath,
        "/ssrf/header-url" bind GET to ::ssrfHeaderUrl,

        // Path Injection
        "/path/query" bind GET to ::pathQuery,
        "/path/header" bind GET to ::pathHeader,

        // SQL Injection
        "/sql/query" bind GET to ::sqlQuery,
        "/sql/form" bind POST to ::sqlForm,
        "/sql/formMap" bind POST to ::sqlFormMap,
        "/sql/header" bind GET to ::sqlHeader,
        "/sql/cookie" bind GET to ::sqlCookie,
        "/sql/bearer" bind GET to ::sqlBearer,
        "/sql/json" bind POST to ::sqlJson,

        // Command Injection
        "/cmd/query" bind GET to ::cmdQuery,
        "/cmd/header" bind GET to ::cmdHeader,
        "/cmd/body" bind POST to ::cmdBody,

        // Multipart
        "/multi/field-xss" bind POST to ::multiFieldXss,
        "/multi/file-name" bind POST to ::multiFileName,

        // Lens
        "/lens/query-extract" bind GET to ::lensQueryExtract,
        "/lens/body-extract" bind POST to ::lensBodyExtract,
        "/lens/extractor" bind GET to ::lensExtractorGet,

        // Auth Headers
        "/auth/bearer-sql" bind GET to ::authBearerSql,
        "/auth/basic-xss" bind GET to ::authBasicXss,

        // URI / Template
        "/uri/credentials" bind GET to ::uriCredentials,
        "/uri/request-source" bind GET to ::uriRequestSource,

        // Misc
        "/misc/parse" bind POST to ::miscParse,
        "/misc/curl" bind GET to ::miscCurl,
        "/misc/params" bind GET to ::miscParams,
        "/misc/json-convert" bind POST to ::miscJsonConvert,

        // Client SSRF
        "/client/okhttp" bind GET to ::ssrfOkHttp,
        "/client/jetty" bind GET to ::ssrfJettyClient,
        "/client/okhttp-uri" bind GET to ::ssrfOkHttpUri,
        "/client/okhttp-async" bind GET to ::ssrfOkHttpAsync,

        // Log Injection
        "/log/query" bind GET to ::logQuery,
        "/log/header" bind GET to ::logHeader,
        "/log/form" bind POST to ::logForm,

        // Response Splitting
        "/split/header-name" bind GET to ::splitHeaderName,
        "/split/header-value" bind GET to ::splitHeaderValue,

        // Lens Injection
        "/lens/inject-xss" bind GET to ::lensInjectXss,

        // Result4k taint flow
        "/result4k/success" bind GET to ::result4kSuccessXss,
        "/result4k/success-component1" bind GET to ::result4kSuccessComponent1,
        "/result4k/failure-reason" bind GET to ::result4kFailureReason,
        "/result4k/failure-component1" bind GET to ::result4kFailureComponent1,
        "/result4k/as-success" bind GET to ::result4kAsSuccess,
        "/result4k/as-failure" bind GET to ::result4kAsFailure,
        "/result4k/map" bind GET to ::result4kMapXss,
        "/result4k/flatmap" bind GET to ::result4kFlatMap,
        "/result4k/mapfailure" bind GET to ::result4kMapFailure,
        "/result4k/flatmapfailure" bind GET to ::result4kFlatMapFailure,
        "/result4k/recover" bind GET to ::result4kRecover,
        "/result4k/onfailure" bind GET to ::result4kOnFailure,
        "/result4k/peek" bind GET to ::result4kPeek,
        "/result4k/peekfailure" bind GET to ::result4kPeekFailure,
        "/result4k/value-or-null" bind GET to ::result4kValueOrNullXss,
        "/result4k/as-result-or" bind GET to ::result4kAsResultOr,

        // Handlebars template
        "/template/handlebars-xss" bind GET to ::handlebarsXss,
        "/template/handlebars-ssti" bind GET to ::handlebarsSsti,
        "/template/handlebars-apply-writer" bind GET to ::handlebarsApplyWriter,
        "/template/handlebars-apply-context" bind GET to ::handlebarsApplyContext,
        "/template/handlebars-apply-context-map" bind GET to ::handlebarsApplyContextMap,
        "/template/handlebars-compile-delims" bind GET to ::handlebarsCompileInlineDelims,
        "/template/render-to-response" bind GET to ::templateRenderToResponse,

        // Sanitizer barrier validation — control (MUST alert) vs treatment (MUST NOT alert)
        "/sanitizer/path-control" bind GET to ::pathControlUnsanitized,
        "/sanitizer/path-resolved-within-root" bind GET to ::pathResolvedWithinRoot
    )

    val server = app.asServer(Netty(8080)).start()
    println("Vulnerable http4k server started on http://localhost:8080")
}
