package com.example.vulnerable.routes

import org.http4k.core.*

// Source: Uri.credentials() → Sink: Response.body(String)
fun uriCredentials(request: Request): Response {
    val creds = request.uri.credentials()
    val display = creds?.let { "${it.user}:${it.password}" } ?: "none"
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Credentials: $display</body></html>")
}

// Source: RequestSource.getAddress() → Sink: Response.body(String)
fun uriRequestSource(request: Request): Response {
    val source = request.source
    val address = source?.address ?: "unknown"
    val scheme = source?.scheme ?: "unknown"
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>From: $address via $scheme</body></html>")
}
