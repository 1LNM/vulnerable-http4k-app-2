package com.example.vulnerable.routes

import com.natpryce.krouton.`string`
import com.natpryce.krouton.`int`
import com.natpryce.krouton.parse
import org.http4k.core.*

// Krouton path extraction. `string`/`int` are VariablePathElement (extends PathElement).

// VariablePathElement.parsePathElement(String) → String  (overrides PathElement)
fun kroutonParseString(request: Request): Response {
    val input = request.query("segment") ?: "default"
    val parsed = `string`.parsePathElement(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}

// int element: parsePathElement(String) → Int?
fun kroutonParseInt(request: Request): Response {
    val input = request.query("segment") ?: "0"
    val parsed = `int`.parsePathElement(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}

// PathTemplate.parse(String) → T — real-world route extraction.
// `string` is a VariablePathElement, which is a PathTemplate<String>.
// parse is an extension function (compiles to PathTemplateKt.parse(PathTemplate, String)).
// KNOWN GAP: this endpoint does NOT fire. The parse summary (Arg[1]->Return) is kept for
// real-world coverage, but our synthetic single-element parse doesn't trigger CodeQL flow
// (parse internally degenerates to splitPath -> parse(template, List)). The parsePathElement
// primitive above (which parse delegates to) IS detected, so extraction is covered.
fun kroutonParseTemplate(request: Request): Response {
    val input = request.query("segment") ?: "default"
    val parsed = `string`.parse(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}
