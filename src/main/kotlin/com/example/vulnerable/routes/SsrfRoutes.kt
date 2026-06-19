package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.core.Method.GET

// Source: Request.query() → Summary: Uri.of() → Sink: Request.uri(Uri)
fun ssrfUriSet(request: Request): Response {
    val target = request.query("target") ?: "http://localhost"
    val outbound = Request(GET, "http://default").uri(Uri.of(target))
    return Response(Status.OK).body("Would fetch: ${outbound.uri}")
}

// Source: Request.query() → Sink: Request(Method, String)
fun ssrfRequestCreate(request: Request): Response {
    val url = request.query("url") ?: "http://localhost"
    val outbound = Request(GET, url)
    return Response(Status.OK).body("Would fetch: ${outbound.uri}")
}

// Source: Request.query() → Summary: Uri.of() → Sink: Uri.extend(Uri)
fun ssrfExtend(request: Request): Response {
    val ext = request.query("ext") ?: ""
    val base = Uri.of("http://api.internal")
    val extended = base.extend(Uri.of(ext))
    return Response(Status.OK).body("Extended: $extended")
}

// Source: Request.query() → Sink: Uri.relative(String)
fun ssrfRelative(request: Request): Response {
    val rel = request.query("rel") ?: ""
    val base = Uri.of("http://api.internal/v1/")
    val resolved = base.relative(rel)
    return Response(Status.OK).body("Resolved: $resolved")
}

// Source: Request.query() → Sink: Uri.appendToPath(String)
fun ssrfAppendPath(request: Request): Response {
    val path = request.query("path") ?: ""
    val base = Uri.of("http://api.internal")
    val appended = base.appendToPath(path)
    return Response(Status.OK).body("Appended: $appended")
}

// Source: Request.header() → Summary: Uri.host() → Sink: Request.uri(Uri)
fun ssrfHeaderUrl(request: Request): Response {
    val host = request.header("X-Target") ?: "localhost"
    val uri = Uri.of("http://placeholder").host(host)
    val outbound = Request(GET, "http://default").uri(uri)
    return Response(Status.OK).body("Would fetch: ${outbound.uri}")
}
