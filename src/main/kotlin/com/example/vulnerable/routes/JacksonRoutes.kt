package com.example.vulnerable.routes

import com.fasterxml.jackson.databind.ObjectMapper
import org.http4k.core.*

// Each endpoint tests one Jackson readTree/JsonNode model entry with an inline sink.

private val mapper = ObjectMapper()

fun jacksonReadTreeGet(request: Request): Response {
    val body = request.bodyString()
    val node = mapper.readTree(body)
    val value = node.get("field").asText()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonGetInt(request: Request): Response {
    val body = request.bodyString()
    val arr = mapper.readTree(body)
    val value = arr.get(0).asText()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonPath(request: Request): Response {
    val body = request.bodyString()
    val node = mapper.readTree(body)
    val value = node.path("field").asText()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonPathInt(request: Request): Response {
    val body = request.bodyString()
    val arr = mapper.readTree(body)
    val value = arr.path(0).asText()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonAt(request: Request): Response {
    val body = request.bodyString()
    val node = mapper.readTree(body)
    val value = node.at("/nested/field").asText()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonFindValue(request: Request): Response {
    val body = request.bodyString()
    val node = mapper.readTree(body)
    val value = node.findValue("field")?.asText() ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonFindPath(request: Request): Response {
    val body = request.bodyString()
    val node = mapper.readTree(body)
    val value = node.findPath("field").asText()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}

fun jacksonTextValue(request: Request): Response {
    val body = request.bodyString()
    val node = mapper.readTree(body)
    val value = node.get("field").textValue()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>$value</html>")
}
