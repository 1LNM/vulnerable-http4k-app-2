package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.routing.ResourceLoader

// CONTROL endpoints for sanitizer (barrier) validation.
// These are the UNSANITIZED twins of the endpoints in SanitizerRoutes.kt — byte-for-byte
// identical EXCEPT they do NOT call the sanitizer. They MUST produce alerts. The whole point
// of the control/treatment pair is that the only difference between this file and
// SanitizerRoutes.kt is the sanitizer call, so a missing alert in the treatment can be
// attributed to the sanitizer and nothing else.

private val loader = ResourceLoader.Classpath("/public", muteWarning = true)

// Control for pathResolvedWithinRoot — MUST alert java/path-injection.
fun pathControlUnsanitized(request: Request): Response {
    val file = request.query("file") ?: "index.html"
    val resource = loader.load(file)
    return if (resource != null) {
        Response(Status.OK).body(resource.readText())
    } else {
        Response(Status.NOT_FOUND).body("Not found")
    }
}
