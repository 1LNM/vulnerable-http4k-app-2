package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.core.body.form
import java.util.logging.Logger

private val logger = Logger.getLogger("vulnerable-app")

// Source: Request.query() → Sink: Logger.info()
fun logQuery(request: Request): Response {
    val name = request.query("name") ?: "anonymous"
    logger.info("User accessed page: $name")
    return Response(Status.OK).body("Logged")
}

// Source: Request.header() → Sink: Logger.warning()
fun logHeader(request: Request): Response {
    val agent = request.header("User-Agent") ?: "unknown"
    logger.warning("Request from agent: $agent")
    return Response(Status.OK).body("Logged")
}

// Source: FormBodyKt.form() → Sink: Logger.info()
fun logForm(request: Request): Response {
    val username = request.form("username") ?: "unknown"
    logger.info("Login attempt for user: $username")
    return Response(Status.OK).body("Logged")
}
