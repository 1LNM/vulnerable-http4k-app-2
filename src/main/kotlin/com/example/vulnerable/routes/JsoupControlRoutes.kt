package com.example.vulnerable.routes

import org.http4k.core.*
import org.jsoup.Jsoup

// CONTROL endpoints: must alert java/xss (proves the Jsoup parse→text flow works).
// Twin of JsoupRoutes.kt which adds Jsoup.clean barrier.

// Jsoup.parse(input).text() — taint flows through parse + text summaries
fun jsoupParseText(request: Request): Response {
    val input = request.query("data") ?: "default"
    val doc = Jsoup.parse(input)
    val text = doc.text()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$text</html>")
}

// Jsoup.parseBodyFragment(input).html() — taint flows through parseBodyFragment + html summaries
fun jsoupParseHtml(request: Request): Response {
    val input = request.query("data") ?: "default"
    val doc = Jsoup.parseBodyFragment(input)
    val html = doc.html()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$html</html>")
}
