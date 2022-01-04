package dev.vusi.ktor.authsample.app

import io.ktor.application.*
import io.ktor.response.*
import io.ktor.request.*
import io.ktor.features.*
import org.slf4j.event.*
import io.ktor.routing.*
import io.ktor.http.*
import io.ktor.auth.*
import com.fasterxml.jackson.databind.*
import com.google.auth.oauth2.GoogleCredentials
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import io.ktor.jackson.*
import io.ktor.server.engine.*
import dev.vusi.ktor.authsample.feature.FirebaseUserPrincipal
import dev.vusi.ktor.authsample.feature.firebase

fun main(args: Array<String>): Unit = io.ktor.server.cio.EngineMain.main(args)

@Suppress("unused") // Referenced in application.conf
fun Application.module(testing: Boolean = false) {

    /**
     * init our Firebase instance first
     */
    initializeFirebase()

    install(CallLogging) {
        level = Level.INFO
        filter { call -> call.request.path().startsWith("/") }
    }

    /**
     * We install firebase here, don't forget to specify a config name
     */
    install(Authentication) {
        firebase("firebaseAuth") {
            validate { credential ->
                if (credential.uid != null && credential.email != null) {
                    FirebaseUserPrincipal(uid = credential.uid, emailAddress = credential.email)
                } else {
                    null
                }
            }
        }
    }

    install(ContentNegotiation) {
        jackson {
            enable(SerializationFeature.INDENT_OUTPUT)
        }
    }

    routing {
        get("/") {
            call.respond(HttpStatusCode.OK, mapOf("message" to "Hello World!"))
        }

        /**
         * These routes require firebase auth in order to get validated.
         * NOTE the configuration name: for the authenticate block
         */
        authenticate("firebaseAuth") {
            get("/protected/route/basic") {
                val principal = call.principal<FirebaseUserPrincipal>()!!
                call.respond(HttpStatusCode.OK, mapOf("message" to "Hello ${principal.uid} with email ${principal.emailAddress}"))
            }
        }
    }
}

/**
 * Update your Firebase json filename below in order to load it correctly, otherwise the server will crash
 *
 */
private fun initializeFirebase() {
    val firebaseConfig = applicationEngineEnvironment { }.classLoader
        .getResourceAsStream("yourjsonfilename.json")

    val firebaseOptions = FirebaseOptions.builder()
        .setCredentials(GoogleCredentials.fromStream(firebaseConfig))
        .setDatabaseUrl("https://yourefirebaseurl.firebaseio.com/")
        .build()

    FirebaseApp.initializeApp(firebaseOptions)
}