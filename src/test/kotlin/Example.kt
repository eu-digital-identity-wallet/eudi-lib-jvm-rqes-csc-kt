/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import eu.europa.ec.eudi.rqes.*
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.auth.*
import io.ktor.client.plugins.auth.providers.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.logging.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import java.io.File
import java.io.FileInputStream
import java.net.URI
import java.security.cert.X509Certificate
import java.time.Clock
import java.util.*
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

val client_id = "wallet-client-tester"
val client_secret = "somesecrettester2"

private fun getUnsafeOkHttpClient(): OkHttpClient {
    // Create a trust manager that does not validate certificate chains
    val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        }

        override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
    })

    // Install the all-trusting trust manager
    val sslContext = SSLContext.getInstance("SSL")
    sslContext.init(null, trustAllCerts, java.security.SecureRandom())
    // Create an ssl socket factory with our all-trusting manager
    val sslSocketFactory = sslContext.socketFactory

    return OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory, trustAllCerts[0] as X509TrustManager)
        .hostnameVerifier { _, _ -> true }.build()
}

private val unsafeHttpClientFactory: KtorHttpClientFactory = {
    HttpClient(OkHttp) {
        install(ContentNegotiation) {
            json(
                json = JsonSupport,
            )
        }
        install(Auth) {
            basic {
                credentials {
                    BasicAuthCredentials(username = client_id, password = client_secret)
                }
                realm = "Access to the '/' path"
            }
        }
        install(Logging) {
            level = LogLevel.ALL
        }

        engine {
            preconfigured = getUnsafeOkHttpClient()
        }
    }
}

private var cscClientConfig = CSCClientConfig(
    OAuth2Client.Confidential.PasswordProtected(client_id, client_secret),
    URI("https://oauthdebugger.com/debug"),
    URI("https://walletcentric.signer.eudiw.dev").toURL(),
    ParUsage.IfSupported,
)

fun main() {
    runBlocking {
        // create the CSC client
        val cscClient: CSCClient = CSCClient.oauth2(
            cscClientConfig,
            "https://walletcentric.signer.eudiw.dev/csc/v2",
            unsafeHttpClientFactory,
        ).getOrThrow()

        val rsspMetadata = cscClient.rsspMetadata

        with(cscClient) {
            val walletState = UUID.randomUUID().toString()

            // initiate the service authorization request
            val serviceAuthRequestPrepared = prepareServiceAuthorizationRequest(walletState).getOrThrow()

            println("Use the following URL to authenticate:\n${serviceAuthRequestPrepared.value.authorizationCodeURL}")

            println("Enter the authorization code:")
            val serviceAuthorizationCode = AuthorizationCode(readln())

            val authorizedServiceRequest = with(serviceAuthRequestPrepared) {
                // provide the authorization code to the client
                authorizeWithAuthorizationCode(serviceAuthorizationCode, walletState).getOrThrow()
                    .also { println("Access token:\n${it.tokens.accessToken.accessToken}") }
            }

            // retrieve the credentials from the RSSP
            val credentials = with(authorizedServiceRequest) {
                listCredentials(CredentialsListRequest(certificates = Certificates.Chain)).getOrThrow()
            }

            val document = Document(
                FileInputStream(File(ClassLoader.getSystemResource("sample.pdf").path)),
                "sample pdf",
            )
            val documentToSign = DocumentToSign(
                document,
                SignatureFormat.P,
                ConformanceLevel.ADES_B_B,
                SigningAlgorithmOID.ECDSA_SHA256,
                SignedEnvelopeProperty.ENVELOPED,
                ASICContainer.NONE,
            )

            // initiate the credential authorization request flow
            val credAuthRequestPrepared = with(authorizedServiceRequest) {
                prepareCredentialAuthorizationRequest(credentials.first(), listOf(documentToSign)).getOrThrow()
            }

            println("Use the following URL to authenticate:\n${credAuthRequestPrepared.value.authorizationCodeURL}")

            val credentialAuthorizationCode = AuthorizationCode(readln())

            // provide the credential authorization code to the CSC client
            val credentialAuthorized = with(credAuthRequestPrepared) {
                authorizeWithAuthorizationCode(
                    credentialAuthorizationCode,
                    walletState,
                ).getOrThrow()
            }

            println("Authorized credential request:\n$credentialAuthorized")

            require(credentialAuthorized is CredentialAuthorized.SCAL2) { "Expected SCAL2" }

//            val signatures = with(credentialAuthorized) {
//                signHash(SigningAlgorithmOID.ECDSA_SHA256).getOrThrow()
//            }
//
//            println("Signatures: $signatures")

            val signedDoc = with(credentialAuthorized) {
                signDoc(listOf(documentToSign), SigningAlgorithmOID.ECDSA_SHA256, Clock.systemUTC()).getOrThrow()
            }
        }
    }
}
