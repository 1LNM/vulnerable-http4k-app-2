package com.example.vulnerable.routes

import freemarker.template.Configuration
import freemarker.template.Template
import freemarker.template.Version
import org.http4k.core.*
import java.io.StringReader
import java.io.StringWriter

// Tests whether CodeQL natively models FreeMarker (Freemarker.qll + dedicated queries).
// No custom MaD model file — if alerts fire, CodeQL handles it natively.

private val fmConfig = Configuration(Version("2.3.31"))

// SSTI: user input IS the template string
fun freemarkerSsti(request: Request): Response {
    val input = request.query("template") ?: "Hello"
    val template = Template("t", StringReader(input), fmConfig)
    val writer = StringWriter()
    template.process(emptyMap<String, Any>(), writer)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body(writer.toString())
}

// SSTI: user input as template name loaded from config
fun freemarkerGetTemplate(request: Request): Response {
    val name = request.query("name") ?: "default.ftl"
    val template = fmConfig.getTemplate(name)
    val writer = StringWriter()
    template.process(emptyMap<String, Any>(), writer)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body(writer.toString())
}

// XSS: user data flows through template data model into rendered output
fun freemarkerDataXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val template = Template("t", StringReader("\${name}"), fmConfig)
    val model = mapOf("name" to input)
    val writer = StringWriter()
    template.process(model, writer)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>${writer.toString()}</html>")
}
