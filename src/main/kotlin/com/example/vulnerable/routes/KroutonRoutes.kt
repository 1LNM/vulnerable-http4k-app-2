package com.example.vulnerable.routes

import com.natpryce.krouton.root
import com.natpryce.krouton.`string`
import com.natpryce.krouton.div
import com.natpryce.krouton.parse
import org.http4k.core.*

// Krouton path extraction: tainted URL path → route parse → extracted value → body

private val userRoute = root / "users" / `string`

// Route parse: URI path → krouton template parse → extracted string → body
fun kroutonPathString(request: Request): Response {
    val path = request.uri.path
    val parsed = userRoute.parse(path)
    val value = parsed?.component1() ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>User: $value</html>")
}

// PathElementType.parsePathElement: direct segment parsing
fun kroutonParseElement(request: Request): Response {
    val input = request.query("segment") ?: "default"
    val parsed = `string`.parsePathElement(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}
