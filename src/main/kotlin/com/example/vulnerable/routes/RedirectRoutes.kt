package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.core.cookie.cookie
import org.http4k.lens.location

// Source: Request.query() → Sink: Response.header("Location", tainted)
fun redirectHeader(request: Request): Response {
    val url = request.query("url") ?: "/"
    return Response(Status.FOUND)
        .header("Location", url)
}

// Source: Request.query() → Sink: Response.replaceHeader("Location", tainted)
fun redirectReplace(request: Request): Response {
    val url = request.query("url") ?: "/"
    return Response(Status.FOUND)
        .header("Location", "/default")
        .replaceHeader("Location", url)
}

// Source: Request.query() → Summary: Uri.of() → Sink: HeaderKt.location()
fun redirectLocation(request: Request): Response {
    val url = request.query("url") ?: "/"
    val uri = Uri.of(url)
    return Response(Status.FOUND).location(uri)
}

// Source: Request.query() → Summary: UriTemplate.generate() → Sink: Response.header
fun redirectTemplate(request: Request): Response {
    val id = request.query("id") ?: "0"
    val template = UriTemplate.from("/users/{id}/profile")
    val generated = template.generate(mapOf("id" to id))
    return Response(Status.FOUND)
        .header("Location", generated)
}

// Source: CookieExtensionsKt.cookie() → Summary: Cookie.getValue() → Sink: Response.header
fun redirectCookieSrc(request: Request): Response {
    val redirectCookie = request.cookie("redirect_to")
    val url = redirectCookie?.value ?: "/"
    return Response(Status.FOUND)
        .header("Location", url)
}
