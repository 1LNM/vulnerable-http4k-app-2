package com.example.vulnerable.routes

import arrow.core.Option
import arrow.core.getOrElse
import arrow.core.orNull
import org.http4k.core.*

// Arrow-kt Option: wrap/unwrap tainted data

fun arrowOptionOrNull(request: Request): Response {
    val input = request.query("data")
    val value = Option.fromNullable(input).orNull()
    if (value != null) {
        return Response(Status.OK).header("Content-Type", "text/html")
            .body("<html>$value</html>")
    }
    return Response(Status.OK).body("no value")
}

fun arrowOptionGetOrElse(request: Request): Response {
    val input = request.query("data")
    val value = Option.fromNullable(input).getOrElse { "default" }
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun arrowOptionMap(request: Request): Response {
    val input = request.query("data")
    val value = Option.fromNullable(input).map { it.uppercase() }.orNull()
    if (value != null) {
        return Response(Status.OK).header("Content-Type", "text/html")
            .body("<html>$value</html>")
    }
    return Response(Status.OK).body("no value")
}
