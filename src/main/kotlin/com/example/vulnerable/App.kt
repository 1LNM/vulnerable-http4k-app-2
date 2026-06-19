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
        "/misc/json-convert" bind POST to ::miscJsonConvert
    )

    val server = app.asServer(Netty(8080)).start()
    println("Vulnerable http4k server started on http://localhost:8080")
}
