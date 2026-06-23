package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.routing.ResourceLoader
import org.http4k.routing.resolvedWithinRoot

// TREATMENT endpoints for sanitizer (barrier) validation.
// Each function is an exact copy of its CONTROL twin in SanitizerControlRoutes.kt, with the
// ONLY difference being the sanitizer call. These MUST NOT produce alerts — the barrier model
// (e.g. resolvedWithinRoot -> path-injection) blocks the taint. The deterministic harness
// (scripts/check_findings.py) asserts this file contains zero alerts of the relevant rule,
// while the control file contains the matching alert.

private val loader = ResourceLoader.Classpath("/public", muteWarning = true)

// Treatment for pathControlUnsanitized — resolvedWithinRoot() barrier; MUST NOT alert.
fun pathResolvedWithinRoot(request: Request): Response {
    val file = request.query("file") ?: "index.html"
    val safe = file.resolvedWithinRoot() ?: return Response(Status.BAD_REQUEST).body("invalid path")
    val resource = loader.load(safe)
    return if (resource != null) {
        Response(Status.OK).body(resource.readText())
    } else {
        Response(Status.NOT_FOUND).body("Not found")
    }
}
