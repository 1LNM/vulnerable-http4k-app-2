package com.example.vulnerable.routes

import com.natpryce.krouton.PathElementType
import com.natpryce.krouton.splitPath
import org.http4k.core.*

// Krouton path extraction: tainted URL path → splitPath → segments → body

// splitPath: URL path string → List<String> segments
fun kroutonSplitPath(request: Request): Response {
    val path = request.uri.path
    val segments = splitPath(path)
    val value = segments.firstOrNull() ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Segment: $value</html>")
}

// PathElementType.parsePathElement: segment string → typed value
fun kroutonParseElement(request: Request): Response {
    val input = request.query("segment") ?: "default"
    val stringType: PathElementType<String> = com.natpryce.krouton.`string`
    val parsed = stringType.parsePathElement(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}
