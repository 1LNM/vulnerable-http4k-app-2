package com.example.vulnerable.routes

import org.http4k.client.OkHttp
import org.http4k.client.JettyClient
import org.http4k.core.*
import org.http4k.core.Method.GET

// Source: Request.query() → Sink: DualSyncAsyncHttpHandler.invoke(Request) via OkHttp
fun ssrfOkHttp(request: Request): Response {
    val target = request.query("target") ?: "http://localhost"
    val client = OkHttp()
    val result = client(Request(GET, target))
    client.close()
    return Response(Status.OK).body("Fetched: ${result.status}")
}

// Source: Request.header() → Sink: DualSyncAsyncHttpHandler.invoke(Request) via JettyClient
fun ssrfJettyClient(request: Request): Response {
    val target = request.header("X-Fetch-Url") ?: "http://localhost"
    val client = JettyClient()
    val result = client(Request(GET, target))
    client.close()
    return Response(Status.OK).body("Fetched: ${result.status}")
}

// Source: Request.query() → Summary: Uri.of → Sink: DualSyncAsyncHttpHandler.invoke(Request)
fun ssrfOkHttpUri(request: Request): Response {
    val target = request.query("target") ?: "http://localhost/api/data"
    val client = OkHttp()
    val result = client(Request(GET, Uri.of(target)))
    client.close()
    return Response(Status.OK).body("Fetched: ${result.status}")
}

// Source: Request.query() → Sink: AsyncHttpHandler.invoke(Request, callback)
fun ssrfOkHttpAsync(request: Request): Response {
    val target = request.query("target") ?: "http://localhost"
    val client = OkHttp()
    var asyncResult = ""
    client(Request(GET, target)) { response ->
        asyncResult = "Fetched: ${response.status}"
    }
    client.close()
    return Response(Status.OK).body(asyncResult)
}
