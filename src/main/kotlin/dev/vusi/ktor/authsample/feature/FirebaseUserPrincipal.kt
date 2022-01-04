package dev.vusi.ktor.authsample.feature

import io.ktor.auth.*

data class FirebaseUserPrincipal(val uid: String, val emailAddress: String) : Principal