package com.example.vulnerable.routes

import org.http4k.core.*
import org.jsoup.Jsoup
import org.jsoup.safety.Safelist

// TREATMENT endpoint: must NOT alert java/xss (Jsoup.clean barrier strips HTML).
// Twin of JsoupControlRoutes.kt which omits the sanitizer.

fun jsoupClean(request: Request): Response {
    val input = request.query("data") ?: "default"
    val safe = Jsoup.clean(input, Safelist.none())
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$safe</html>")
}
