package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.lens.basicAuthentication
import org.http4k.lens.bearerToken
import java.sql.DriverManager

private fun unsafeQuery(input: String): String {
    val conn = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1")
    return conn.use {
        try {
            val rs = it.createStatement().executeQuery("SELECT * FROM users WHERE name = '$input'")
            val results = mutableListOf<String>()
            while (rs.next()) results.add("${rs.getInt("id")}: ${rs.getString("name")}")
            results.joinToString("\n").ifEmpty { "No results" }
        } catch (e: Exception) { "Error: ${e.message}" }
    }
}

// Source: HeaderKt.bearerToken() → Sink: Statement.executeQuery()
fun authBearerSql(request: Request): Response {
    val token = request.bearerToken() ?: ""
    val result = unsafeQuery(token)
    return Response(Status.OK).body(result)
}

// Source: HeaderKt.basicAuthentication() → Sink: Response.body(String)
fun authBasicXss(request: Request): Response {
    val creds = request.basicAuthentication()
    val user = creds?.user ?: "anonymous"
    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body("<html><body>Welcome $user</body></html>")
}
