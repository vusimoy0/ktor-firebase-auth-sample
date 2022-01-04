package dev.vusi.ktor.authsample.feature

import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseToken
import io.ktor.application.*
import io.ktor.auth.*
import io.ktor.http.auth.*
import io.ktor.request.*
import io.ktor.response.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class FirebaseAuthenticationProvider(config: Configuration) : AuthenticationProvider(config) {

    val authHeader: (ApplicationCall) -> HttpAuthHeader? = config.authHeader
    val authFunction = config.firebaseAuthenticationFunction

    class Configuration(configName: String) : AuthenticationProvider.Configuration(configName) {

        internal var authHeader: (ApplicationCall) -> HttpAuthHeader? =
            { call -> call.request.parseAuthorizationHeaderOrNull() }


        var firebaseAuthenticationFunction: AuthenticationFunction<FirebaseToken> = {
            throw NotImplementedError(FirebaseImplementationError)
        }

        fun validate(validate: suspend ApplicationCall.(FirebaseToken) -> FirebaseUserPrincipal?) {
            firebaseAuthenticationFunction = validate
        }

        fun build() = FirebaseAuthenticationProvider(this)
    }
}

//ref: //Thanks to this url: https://www.scottbrady91.com/kotlin/json-web-token-verification-in-ktor-using-kotlin-and-java-jwt
fun Authentication.Configuration.firebase(
    configName: String = "firebaseAuth",
    configure: FirebaseAuthenticationProvider.Configuration.() -> Unit
) {
    val provider = FirebaseAuthenticationProvider.Configuration(configName).apply(configure).build()
    val authenticate = provider.authFunction

    provider.pipeline.intercept(AuthenticationPipeline.RequestAuthentication) { context ->
        val token = provider.authHeader(call)
        if (token == null) {
            context.challenge(FirebaseJWTAuthKey, AuthenticationFailedCause.InvalidCredentials) {
                it.completed
                call.respond(UnauthorizedResponse(HttpAuthHeader.bearerAuthChallenge(realm = "firebaseAuth")))
            }
            return@intercept
        }
        try {
            val principal = verifyFirebaseIdToken(call, token, authenticate)

            if (principal != null) {
                context.principal(principal)
                return@intercept
            }
        } catch (cause: Throwable) {
            val message = cause.message ?: cause.javaClass.simpleName
            context.error(FirebaseJWTAuthKey, AuthenticationFailedCause.Error(message))
        }
    }
    register(provider)
}

//todo implement logger instead of printStackTrace
suspend fun verifyFirebaseIdToken(
    call: ApplicationCall,
    authHeader: HttpAuthHeader,
    tokenData: suspend ApplicationCall.(FirebaseToken) -> Principal?
): Principal? {
    val token: FirebaseToken = try {
        if (authHeader.authScheme == "Bearer" && authHeader is HttpAuthHeader.Single) {
            withContext(Dispatchers.IO) {
                FirebaseAuth.getInstance().verifyIdToken(authHeader.blob)
            }
        } else {
            null
        }
    } catch (ex: Exception) {
        ex.printStackTrace()
        return null
    } ?: return null
    return tokenData(call, token)
}

private fun HttpAuthHeader.Companion.bearerAuthChallenge(realm: String): HttpAuthHeader {
    return HttpAuthHeader.Parameterized("Bearer", mapOf(HttpAuthHeader.Parameters.Realm to realm))
}

//todo - enable logger
private fun ApplicationRequest.parseAuthorizationHeaderOrNull() = try {
    parseAuthorizationHeader()
} catch (ex: IllegalArgumentException) {
    println("failed to parse token")
    null
}

private const val FirebaseJWTAuthKey: String = "FirebaseAuth"
private const val FirebaseImplementationError =
    "Firebase  auth validate function is not specified, use firebase { { ... } }to fix"