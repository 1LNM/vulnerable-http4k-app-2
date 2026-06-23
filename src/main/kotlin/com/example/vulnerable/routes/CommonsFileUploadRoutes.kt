package com.example.vulnerable.routes

import org.apache.commons.fileupload.FileUpload
import org.apache.commons.fileupload.RequestContext
import org.apache.commons.fileupload.disk.DiskFileItemFactory
import org.apache.commons.fileupload.util.Streams
import org.http4k.core.*
import java.io.InputStream

// Tests whether CodeQL natively models commons-fileupload (added in CodeQL 2.24.0).
// No custom MaD model file — if alerts fire, CodeQL handles it natively.

private fun requestContext(request: Request) = object : RequestContext {
    override fun getCharacterEncoding() = "UTF-8"
    override fun getContentType() = request.header("Content-Type") ?: "multipart/form-data"
    override fun getContentLength() = -1
    override fun getInputStream(): InputStream = request.body.stream
}

// XSS via FileItem.getString()
fun commonsUploadGetString(request: Request): Response {
    val upload = FileUpload(DiskFileItemFactory())
    val items = upload.parseRequest(requestContext(request))
    val value = items.firstOrNull()?.getString() ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Field: $value</html>")
}

// XSS via FileItem.getName()
fun commonsUploadGetName(request: Request): Response {
    val upload = FileUpload(DiskFileItemFactory())
    val items = upload.parseRequest(requestContext(request))
    val name = items.firstOrNull()?.name ?: "none"
    return Response(Status.OK).header("Content-Type", "text/html")
        .body("<html>Filename: $name</html>")
}

// XSS via streaming API: FileItemStream.openStream → Streams.asString
fun commonsUploadStream(request: Request): Response {
    val upload = FileUpload()
    val iter = upload.getItemIterator(requestContext(request))
    if (iter.hasNext()) {
        val item = iter.next()
        val content = Streams.asString(item.openStream())
        return Response(Status.OK).header("Content-Type", "text/html")
            .body("<html>Content: $content</html>")
    }
    return Response(Status.OK).body("no items")
}

// XSS via FileItemStream.getFieldName()
fun commonsUploadFieldName(request: Request): Response {
    val upload = FileUpload()
    val iter = upload.getItemIterator(requestContext(request))
    if (iter.hasNext()) {
        val item = iter.next()
        val fieldName = item.fieldName
        return Response(Status.OK).header("Content-Type", "text/html")
            .body("<html>FieldName: $fieldName</html>")
    }
    return Response(Status.OK).body("no items")
}
