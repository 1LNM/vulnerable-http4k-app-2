package com.example.vulnerable.routes

import org.http4k.core.*

// ============================================================
// Test endpoints for comparison plan verification.
// Each tests a specific model entry or CodeQL-native behavior.
// ============================================================

// --- Uri.toString: does taint flow through toString()? ---
// Model: summaryModel Uri.toString Arg[this]→ReturnValue
// Could be CodeQL-native (Java toString is fundamental)
fun uriToStringXss(request: Request): Response {
    val input = request.query("url") ?: "http://default"
    val uri = Uri.of(input)
    val str = uri.toString()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>URI: $str</html>")
}

// --- Uri.copy: does taint flow from receiver through copy()? ---
// Model: summaryModel Uri.copy Arg[this]→ReturnValue
// Kotlin data class copy — may or may not be CodeQL-native
fun uriCopyThisXss(request: Request): Response {
    val input = request.query("url") ?: "http://default"
    val uri = Uri.of(input)
    val copied = uri.copy(path = "/fixed")
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>URI: $copied</html>")
}

// --- Uri.copy: does taint flow from argument through copy()? ---
// Model: summaryModel Uri.copy Arg[0]→ReturnValue
fun uriCopyArgXss(request: Request): Response {
    val input = request.query("path") ?: "/default"
    val safe = Uri.of("http://example.com")
    val copied = safe.copy(path = input)
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>URI: $copied</html>")
}

// --- MultipartFormBody.from: KNOWN GAP ---
// NOT DETECTED. from() has default params → compiles to from$default.
// Tested all type/arg combinations for $default — none match. Break is at from(),
// not fieldValue() (confirmed via diagnostic endpoint that bypassed fieldValue).
fun multiFromFactoryXss(request: Request): Response {
    val mpBody = MultipartFormBody.from(request)
    val value = mpBody.fieldValue("name") ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Field: $value</html>")
}

// --- Neutral model test: request.method echo ---
// Should NOT alert — Method is an enum, not user-controlled data.
// If this fires, we need a neutralModel for Request.getMethod.
fun requestMethodEcho(request: Request): Response {
    val method = request.method.name
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Method: $method</html>")
}
