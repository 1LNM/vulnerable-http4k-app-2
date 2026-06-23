package com.example.vulnerable.routes

import com.github.jknack.handlebars.Handlebars
import org.http4k.core.*

fun handlebarsXss(request: Request): Response {
    val name = request.query("name") ?: "World"
    val handlebars = Handlebars()
    val template = handlebars.compileInline("{{{this}}}")
    val rendered = template.apply(name)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}

fun handlebarsSsti(request: Request): Response {
    val templateStr = request.query("template") ?: "Hello {{name}}"
    val handlebars = Handlebars()
    val template = handlebars.compileInline(templateStr)
    val rendered = template.apply(mapOf("name" to "user"))
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}
