package com.example.vulnerable.routes

import com.github.jknack.handlebars.Context
import com.github.jknack.handlebars.Handlebars
import org.http4k.core.*
import org.http4k.template.HandlebarsTemplates
import org.http4k.template.ViewModel
import org.http4k.template.renderToResponse
import java.io.StringWriter

// --- Template.apply(Object) sink (html-injection) + apply(Object) summary into body ---
fun handlebarsXss(request: Request): Response {
    val name = request.query("name") ?: "World"
    val template = Handlebars().compileInline("{{{this}}}")
    val rendered = template.apply(name)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}

// --- Handlebars.compileInline(String) sink (template-injection / SSTI) ---
fun handlebarsSsti(request: Request): Response {
    val templateStr = request.query("template") ?: "Hello {{name}}"
    val template = Handlebars().compileInline(templateStr)
    val rendered = template.apply(mapOf("name" to "user"))
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}

// --- Template.apply(Object, Writer) sink (html-injection) ---
fun handlebarsApplyWriter(request: Request): Response {
    val name = request.query("name") ?: "World"
    val template = Handlebars().compileInline("{{{this}}}")
    val writer = StringWriter()
    template.apply(name, writer)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(writer.toString())
}

// --- Context.combine(String, Object) summary + Template.apply(Context) sink + summary ---
fun handlebarsApplyContext(request: Request): Response {
    val name = request.query("name") ?: "World"
    val context = Context.newContext("base").combine("user", name)
    val template = Handlebars().compileInline("{{{user}}}")
    val rendered = template.apply(context)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}

// --- Context.combine(Map) summary feeding Template.apply(Context) ---
fun handlebarsApplyContextMap(request: Request): Response {
    val name = request.query("name") ?: "World"
    val context = Context.newContext("base").combine(mapOf("user" to name))
    val template = Handlebars().compileInline("{{{user}}}")
    val rendered = template.apply(context)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}

// --- Handlebars.compileInline(String, String, String) sink (template-injection) ---
fun handlebarsCompileInlineDelims(request: Request): Response {
    val templateStr = request.query("template") ?: "Hello {{name}}"
    val template = Handlebars().compileInline(templateStr, "{{", "}}")
    val rendered = template.apply(mapOf("name" to "user"))
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(rendered)
}

// --- TemplatesKt.renderToResponse(viewModel) sink (html-injection via http4k Templates) ---
data class GreetingView(val name: String) : ViewModel

fun templateRenderToResponse(request: Request): Response {
    val name = request.query("name") ?: "World"
    val renderer = HandlebarsTemplates().HotReload("src/main/resources/templates")
    return renderer.renderToResponse(GreetingView(name))
}
