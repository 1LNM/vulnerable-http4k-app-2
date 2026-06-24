package com.example.vulnerable.routes

import com.natpryce.krouton.`string`
import com.natpryce.krouton.`int`
import com.natpryce.krouton.parse
import org.http4k.core.*

// Krouton path extraction modelled as SOURCES — the extracted value is user input.
// `string`/`int` are VariablePathElement (extends PathElement). parsePathElement is the
// extraction primitive; its ReturnValue is a remote source.

// parsePathElement on the string element → tainted String → body
fun kroutonParseString(request: Request): Response {
    val parsed = `string`.parsePathElement("seg")
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}

// parsePathElement on the int element → tainted Int → body
fun kroutonParseInt(request: Request): Response {
    val parsed = `int`.parsePathElement("123")
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}

// PathTemplate.parse(String) → T — real-world route extraction, modelled as a source.
// `string` is a VariablePathElement, which is a PathTemplate<String>. parse is an
// extension function (PathTemplateKt.parse(PathTemplate, String)); modelled as a source
// on the PathTemplate receiver type to match how route handlers invoke it.
fun kroutonParseTemplate(request: Request): Response {
    val parsed = `string`.parse("seg")
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}
