package com.example.vulnerable.routes

import org.http4k.core.*

// Source: Request.query() → Sink: Runtime.exec()
fun cmdQuery(request: Request): Response {
    val cmd = request.query("cmd") ?: "echo hello"
    val process = Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", cmd))
    val output = process.inputStream.bufferedReader().readText()
    return Response(Status.OK).body(output)
}

// Source: Request.header() → Sink: Runtime.exec()
fun cmdHeader(request: Request): Response {
    val cmd = request.header("X-Cmd") ?: "echo hello"
    val process = Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", cmd))
    val output = process.inputStream.bufferedReader().readText()
    return Response(Status.OK).body(output)
}

// Source: Request.bodyString() → Sink: Runtime.exec()
fun cmdBody(request: Request): Response {
    val cmd = request.bodyString()
    val process = Runtime.getRuntime().exec(arrayOf("/bin/sh", "-c", cmd))
    val output = process.inputStream.bufferedReader().readText()
    return Response(Status.OK).body(output)
}
