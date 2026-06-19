package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.format.Jackson

// Source: raw string → Summary: Request.Companion.parse() → Sink: Response.body(String)
fun miscParse(request: Request): Response {
    val rawHttp = request.bodyString()
    val parsed = Request.parse(rawHttp)
    val body = parsed.bodyString()
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Parsed body: $body</body></html>")
}

// Source: Request (tainted) → Summary: Request.toCurl() → Sink: Response.body(String)
fun miscCurl(request: Request): Response {
    val curlCmd = request.toCurl()
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body><pre>$curlCmd</pre></body></html>")
}

// Source: Request.getUri() → Summary: ParametersKt.toParameters/findSingle → Sink: Response.body(String)
fun miscParams(request: Request): Response {
    val query = request.uri.query
    val params = query.toParameters()
    val value = params.findSingle("key")
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Value: $value</body></html>")
}

// Source: Request.bodyString() → Summary: AutoMarshalling.asFormatString/convert → Sink: Response.body(String)
fun miscJsonConvert(request: Request): Response {
    val body = request.bodyString()
    val node = Jackson.parse(body)
    val output = Jackson.asFormatString(node)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$output</body></html>")
}
