package com.example.vulnerable.routes

import org.http4k.core.*
import org.http4k.core.body.form
import org.http4k.core.body.formAsMap
import org.http4k.core.cookie.cookie
import org.http4k.format.Jackson.asA
import org.http4k.lens.bearerToken
import com.example.vulnerable.model.UserInput
import java.sql.DriverManager

private fun getConnection() = DriverManager.getConnection("jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1")

private fun initDb() {
    getConnection().use { conn ->
        conn.createStatement().execute(
            "CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(255))"
        )
    }
}

private val dbInitialized by lazy { initDb(); true }

private fun executeUnsafeQuery(input: String): String {
    dbInitialized
    return getConnection().use { conn ->
        try {
            val rs = conn.createStatement().executeQuery("SELECT * FROM users WHERE name = '$input'")
            val results = mutableListOf<String>()
            while (rs.next()) {
                results.add("${rs.getInt("id")}: ${rs.getString("name")}")
            }
            results.joinToString("\n").ifEmpty { "No results" }
        } catch (e: Exception) {
            "Error: ${e.message}"
        }
    }
}

// Source: Request.query() → Sink: Statement.executeQuery()
fun sqlQuery(request: Request): Response {
    val id = request.query("id") ?: ""
    val result = executeUnsafeQuery(id)
    return Response(Status.OK).body(result)
}

// Source: FormBodyKt.form() → Sink: Statement.executeQuery()
fun sqlForm(request: Request): Response {
    val name = request.form("name") ?: ""
    val result = executeUnsafeQuery(name)
    return Response(Status.OK).body(result)
}

// Source: FormBodyKt.formAsMap() → Sink: Statement.executeQuery()
fun sqlFormMap(request: Request): Response {
    val formData = request.formAsMap()
    val name = formData["name"]?.firstOrNull() ?: ""
    val result = executeUnsafeQuery(name)
    return Response(Status.OK).body(result)
}

// Source: Request.header() → Sink: Statement.executeQuery()
fun sqlHeader(request: Request): Response {
    val id = request.header("X-Id") ?: ""
    val result = executeUnsafeQuery(id)
    return Response(Status.OK).body(result)
}

// Source: CookieExtensionsKt.cookie() → Summary: Cookie.getValue() → Sink: Statement.executeQuery()
fun sqlCookie(request: Request): Response {
    val session = request.cookie("session")
    val id = session?.value ?: ""
    val result = executeUnsafeQuery(id)
    return Response(Status.OK).body(result)
}

// Source: HeaderKt.bearerToken() → Sink: Statement.executeQuery()
fun sqlBearer(request: Request): Response {
    val token = request.bearerToken() ?: ""
    val result = executeUnsafeQuery(token)
    return Response(Status.OK).body(result)
}

// Source: Request.bodyString() → Summary: AutoMarshalling.asA() → Sink: Statement.executeQuery()
fun sqlJson(request: Request): Response {
    val body = request.bodyString()
    val input = asA<UserInput>(body)
    val result = executeUnsafeQuery(input.name)
    return Response(Status.OK).body(result)
}
