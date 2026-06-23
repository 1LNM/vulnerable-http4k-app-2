package com.example.vulnerable.routes

import dev.forkhandles.result4k.Failure
import dev.forkhandles.result4k.Success
import dev.forkhandles.result4k.asFailure
import dev.forkhandles.result4k.asResultOr
import dev.forkhandles.result4k.asSuccess
import dev.forkhandles.result4k.flatMap
import dev.forkhandles.result4k.flatMapFailure
import dev.forkhandles.result4k.map
import dev.forkhandles.result4k.mapFailure
import dev.forkhandles.result4k.onFailure
import dev.forkhandles.result4k.peek
import dev.forkhandles.result4k.peekFailure
import dev.forkhandles.result4k.recover
import dev.forkhandles.result4k.valueOrNull
import org.http4k.core.*

// Each endpoint has its OWN inline Response.body sink so CodeQL reports a distinct
// alert per result4k model entry (a shared helper would consolidate them into one).

// --- Success constructor + getValue ---
fun result4kSuccessXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val value = Success(input).value
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- Success.component1 (destructuring) ---
fun result4kSuccessComponent1(request: Request): Response {
    val input = request.query("data") ?: "default"
    val (value) = Success(input)
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- Failure constructor + getReason ---
fun result4kFailureReason(request: Request): Response {
    val input = request.query("data") ?: "default"
    val reason = Failure(input).reason
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$reason</html>")
}

// --- Failure.component1 (destructuring) ---
fun result4kFailureComponent1(request: Request): Response {
    val input = request.query("data") ?: "default"
    val (reason) = Failure(input)
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$reason</html>")
}

// --- ResultKt.asSuccess (returns Result; cast to Success to read value) ---
fun result4kAsSuccess(request: Request): Response {
    val input = request.query("data") ?: "default"
    @Suppress("UNCHECKED_CAST")
    val value = (input.asSuccess() as Success<String>).value
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- ResultKt.asFailure (returns Result; cast to Failure to read reason) ---
fun result4kAsFailure(request: Request): Response {
    val input = request.query("data") ?: "default"
    @Suppress("UNCHECKED_CAST")
    val reason = (input.asFailure() as Failure<String>).reason
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$reason</html>")
}

// --- ResultKt.map ---
fun result4kMapXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val mapped = Success(input).map { it }
    @Suppress("UNCHECKED_CAST")
    val value = (mapped as Success<String>).value
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- ResultKt.flatMap ---
fun result4kFlatMap(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Success(input).flatMap { Success(it) }
    @Suppress("UNCHECKED_CAST")
    val value = (result as Success<String>).value
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- ResultKt.mapFailure ---
fun result4kMapFailure(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Failure(input).mapFailure { it }
    @Suppress("UNCHECKED_CAST")
    val reason = (result as Failure<String>).reason
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$reason</html>")
}

// --- ResultKt.flatMapFailure ---
fun result4kFlatMapFailure(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Failure(input).flatMapFailure { Failure(it) }
    @Suppress("UNCHECKED_CAST")
    val reason = (result as Failure<String>).reason
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$reason</html>")
}

// --- ResultKt.recover (Failure reason becomes recovered value) ---
fun result4kRecover(request: Request): Response {
    val input = request.query("data") ?: "default"
    val value = Failure(input).recover { it }
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- ResultKt.onFailure (returns Success value) ---
fun result4kOnFailure(request: Request): Response {
    val input = request.query("data") ?: "default"
    val value = Success(input).onFailure { return Response(Status.OK).body("error") }
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- ResultKt.peek (returns Result unchanged) ---
fun result4kPeek(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Success(input).peek { }
    @Suppress("UNCHECKED_CAST")
    val value = (result as Success<String>).value
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}

// --- ResultKt.peekFailure (returns Result unchanged) ---
fun result4kPeekFailure(request: Request): Response {
    val input = request.query("data") ?: "default"
    val result = Failure(input).peekFailure { }
    @Suppress("UNCHECKED_CAST")
    val reason = (result as Failure<String>).reason
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$reason</html>")
}

// --- NullablesKt.valueOrNull ---
fun result4kValueOrNullXss(request: Request): Response {
    val input = request.query("data") ?: "default"
    val value = Success(input).valueOrNull()
    if (value != null) {
        return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
    }
    return Response(Status.OK).body("no value")
}

// --- NullablesKt.asResultOr ---
fun result4kAsResultOr(request: Request): Response {
    val input: String? = request.query("data")
    val result = input.asResultOr { "missing" }
    @Suppress("UNCHECKED_CAST")
    val value = (result as Success<String>).value
    return Response(Status.OK).header("Content-Type", "text/html").body("<html>$value</html>")
}
