package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.lens.Header
import org.http4k.lens.Query
import org.http4k.lens.BiDiBodyLens
import org.http4k.lens.string

// Source: via Lens.invoke(Request) → Sink: Response.body(String)
fun lensQueryExtract(request: Request): Response {
    val nameLens = Query.required("name")
    val name = nameLens(request)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Name: $name</body></html>")
}

// Source: via BodyLens.invoke(Request) → Sink: Response.body(String)
fun lensBodyExtract(request: Request): Response {
    val bodyLens: BiDiBodyLens<String> = Body.string(ContentType.TEXT_PLAIN).toLens()
    val content = bodyLens(request)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$content</body></html>")
}

// Source: via LensExtractor.extract() → Sink: Response.body(String)
fun lensExtractorGet(request: Request): Response {
    val queryLens = Query.required("q")
    val value = queryLens.extract(request)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Search: $value</body></html>")
}

// Source: Request.query() → Sink: LensInjector.inject(tainted, Response) — XSS via lens inject
fun lensInjectXss(request: Request): Response {
    val userInput = request.query("value") ?: "default"
    val headerLens = Header.required("X-Injected")
    return headerLens.inject(userInput, Response(Status.OK).body("Injected"))
}
