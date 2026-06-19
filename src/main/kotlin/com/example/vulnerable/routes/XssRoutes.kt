package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.core.body.form
import org.http4k.lens.html

// Source: Request.query() → Sink: Response.body(String)
fun xssQueryBody(request: Request): Response {
    val input = request.query("input") ?: ""
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Hello $input</body></html>")
}

// Source: Request.bodyString() → Sink: Response.body(String)
fun xssBodyStringBody(request: Request): Response {
    val input = request.bodyString()
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$input</body></html>")
}

// Source: Request.bodyString() via POST → Sink: Response.body(String)
fun xssBodyReflect(request: Request): Response {
    val input = request.bodyString()
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Echo: $input</body></html>")
}

// Source: Request.header() → Sink: HeaderKt.html()
fun xssHeaderHtml(request: Request): Response {
    val input = request.header("X-Input") ?: ""
    return Response(Status.OK).html("<html><body>$input</body></html>")
}

// Source: FormBodyKt.form() → Sink: Response.body(String)
fun xssFormBody(request: Request): Response {
    val input = request.form("name") ?: ""
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Welcome $input</body></html>")
}

// Source: Request.getBody() → Summary: Body.getStream() → Sink: Response.body(String)
fun xssBodyObject(request: Request): Response {
    val bodyStream = request.body.stream
    val content = bodyStream.reader().readText()
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$content</body></html>")
}

// Source: Request.getBody() → Summary: Body.getPayload() → Sink: Response.body(Body)
fun xssBodyStream(request: Request): Response {
    val payload = request.body.payload
    val responseBody = Body(payload)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(responseBody)
}

// Source: Request.queries() → Sink: Response.body(String)
fun xssQueriesBody(request: Request): Response {
    val values = request.queries("q")
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Results: ${values.joinToString()}</body></html>")
}

// Source: Request.headerValues() → Sink: Response.body(String)
fun xssHeaderValuesBody(request: Request): Response {
    val values = request.headerValues("X-Data")
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Headers: ${values.joinToString()}</body></html>")
}

// Source: HttpMessage.getHeaders() → Sink: Response.body(String)
fun xssGetHeadersBody(request: Request): Response {
    val headers = request.headers
    val headerStr = headers.joinToString { "${it.first}: ${it.second}" }
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$headerStr</body></html>")
}
