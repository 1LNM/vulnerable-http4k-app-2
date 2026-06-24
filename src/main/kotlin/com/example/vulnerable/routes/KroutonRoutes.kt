package com.example.vulnerable.routes

import com.natpryce.krouton.`string`
import com.natpryce.krouton.`int`
import org.http4k.core.*

// Krouton path element parsing: exercises PathElementType.parsePathElement model

// string PathElementType: parsePathElement(String) → String
fun kroutonParseString(request: Request): Response {
    val input = request.query("segment") ?: "default"
    val parsed = `string`.parsePathElement(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}

// int PathElementType: parsePathElement(String) → Int?
fun kroutonParseInt(request: Request): Response {
    val input = request.query("segment") ?: "0"
    val parsed = `int`.parsePathElement(input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Parsed: $parsed</html>")
}
