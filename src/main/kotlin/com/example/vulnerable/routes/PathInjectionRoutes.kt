package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.routing.ResourceLoader

private val loader = ResourceLoader.Classpath("/public", muteWarning = true)

// Source: Request.query() → Sink: ResourceLoader.load()
fun pathQuery(request: Request): Response {
    val file = request.query("file") ?: "index.html"
    val resource = loader.load(file)
    return if (resource != null) {
        Response(Status.OK).body(resource.readText())
    } else {
        Response(Status.NOT_FOUND).body("Not found")
    }
}

// Source: Request.header() → Sink: ResourceLoader.load()
fun pathHeader(request: Request): Response {
    val file = request.header("X-File") ?: "index.html"
    val resource = loader.load(file)
    return if (resource != null) {
        Response(Status.OK).body(resource.readText())
    } else {
        Response(Status.NOT_FOUND).body("Not found")
    }
}
