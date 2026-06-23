package com.example.vulnerable.routes

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.http4k.core.*

// JWT claim extraction: bearer token → verify → getClaim → asString → body

private val verifier = JWT.require(Algorithm.HMAC256("secret")).build()

fun jwtClaimXss(request: Request): Response {
    val token = request.header("Authorization")?.removePrefix("Bearer ") ?: return Response(Status.BAD_REQUEST)
    val decoded = verifier.verify(token)
    val sub = decoded.getClaim("sub").asString()
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Subject: $sub</html>")
}

fun jwtClaimList(request: Request): Response {
    val token = request.header("Authorization")?.removePrefix("Bearer ") ?: return Response(Status.BAD_REQUEST)
    val decoded = verifier.verify(token)
    val roles = decoded.getClaim("roles").asList(String::class.java)
    val first = roles.firstOrNull() ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Role: $first</html>")
}
