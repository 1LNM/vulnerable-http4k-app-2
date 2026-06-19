package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.lens.MultipartFormField
import org.http4k.lens.MultipartFormFile
import org.http4k.lens.Validator
import org.http4k.lens.multipartForm
import org.http4k.routing.ResourceLoader

private val multiLoader = ResourceLoader.Classpath("/public", muteWarning = true)

// Source: MultipartFormField.getValue() → Sink: Response.body(String)
fun multiFieldXss(request: Request): Response {
    val nameField = MultipartFormField.required("name")
    val form = Body.multipartForm(Validator.Ignore, nameField).toLens()
    val multiForm = form(request)
    val name = nameField(multiForm)
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Hello ${name.value}</body></html>")
}

// Source: MultipartFormFile.getFilename() → Sink: ResourceLoader.load()
fun multiFileName(request: Request): Response {
    val fileField = MultipartFormFile.required("upload")
    val form = Body.multipartForm(Validator.Ignore, fileField).toLens()
    val multiForm = form(request)
    val file = fileField(multiForm)
    val resource = multiLoader.load(file.filename)
    return if (resource != null) {
        Response(Status.OK).body(resource.readText())
    } else {
        Response(Status.NOT_FOUND).body("Not found: ${file.filename}")
    }
}
