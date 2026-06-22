package com.example.vulnerable.routes

import org.http4k.core.*

// Source: Request.query() → Sink: Response.header(tainted, value) — header name injection
fun splitHeaderName(request: Request): Response {
    val headerName = request.query("header_name") ?: "X-Custom"
    return Response(Status.OK)
        .header(headerName, "some-value")
        .body("Header set")
}

// Source: Request.query() → Sink: Response.header(name, tainted) — header value injection
fun splitHeaderValue(request: Request): Response {
    val headerValue = request.query("header_value") ?: "default"
    return Response(Status.OK)
        .header("X-Custom", headerValue)
        .body("Header set")
}
