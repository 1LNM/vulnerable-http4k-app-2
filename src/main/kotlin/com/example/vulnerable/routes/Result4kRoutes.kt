package com.example.vulnerable.routes

import dev.forkhandles.result4k.Success
import dev.forkhandles.result4k.map
import dev.forkhandles.result4k.valueOrNull
import org.http4k.core.*

fun result4kSuccessXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Success(input)
    val value = result.value
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$value</body></html>")
}

fun result4kMapXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Success(input)
    val mapped = result.map { it }
    val value = (mapped as Success).value
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>$value</body></html>")
}

fun result4kValueOrNullXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Success(input)
    val value = result.valueOrNull()
    if (value != null) {
        return Response(Status.OK)
            .header("Content-Type", "text/html")
            .body("<html><body>$value</body></html>")
    }
    return Response(Status.OK).body("no value")
}
