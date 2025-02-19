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
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.documentretrieval.*
import eu.europa.ec.eudi.rqes.Signature
import eu.europa.ec.eudi.rqes.SignaturesList
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.io.ByteArrayInputStream
import java.time.Clock
import java.time.Duration

fun main() {
    runBlocking {
        val config = DocumentRetrievalConfig(
            jarConfiguration = JarConfiguration(
                supportedRequestUriMethods = SupportedRequestUriMethods.Default,
                supportedAlgorithms = listOf(JWSAlgorithm.HS256),
            ),
            clock = Clock.systemDefaultZone(),
            jarClockSkew = Duration.ofSeconds(15L),
            supportedClientIdSchemes = listOf(
                SupportedClientIdScheme.X509SanUri.NoValidation,
                SupportedClientIdScheme.X509SanDns.NoValidation,
                SupportedClientIdScheme.Preregistered(
                    clients = mapOf<String, PreregisteredClient>(
                        "16b45b1e-3253-436d-a5ef-c235c3f61075" to PreregisteredClient(
                            clientId = "16b45b1e-3253-436d-a5ef-c235c3f61075",
                            legalName = "walletcentric.signer.eudiw.dev",
                            jarConfig = JWSAlgorithm.HS256 to JwkSetSource.ByValue(
                                jwks = Json.parseToJsonElement(
                                    """
                                   {
                                       "keys": [
                                           {
                                               "kty": "oct",
                                               "use": "sig",
                                               "alg": "HS256",
                                               "k": "U0mY7v8Q1w2Z4v6y9B+D-KaPdSgVkXpA"
                                           }
                                       ]
                                   }
                                    """.trimIndent(),
                                ).jsonObject,
                            ),
                        ),
                    ),
                ),
            ),
        )

        val client = DocumentRetrieval(config)

        with(client) {
            var resolution =
                resolveRequestUri(
                    """
                    mdoc-openid4vp://walletcentric.signer.eudiw.dev?
                    request_uri=https://walletcentric.signer.eudiw.dev/rp/wallet/sd/16b45b1e-3253-436d-a5ef-c235c3f61075
                    &client_id=16b45b1e-3253-436d-a5ef-c235c3f61075")
                    """.trimIndent(),
                )

            if (resolution is Resolution.Success) {
                // document signing flow starts here, as shown in the Example.kt file

                // the output of the  signing flow is a list of signed documents and a list of signatures

                val signedDocuments =
                    listOf(
                        ByteArrayInputStream("document1".toByteArray()),
                        ByteArrayInputStream("document2".toByteArray()),
                    )
                val signatureList = SignaturesList(
                    listOf(
                        Signature("signature1"),
                        Signature("signature2"),
                    ),
                )

                dispatch(
                    resolution.requestObject,
                    Consensus.Positive(
                        documentWithSignature = signedDocuments.map { it.readAllBytes().decodeToString() },
                        signatureObject = signatureList.signatures.map { it.value },
                    ),
                )
            }
        }
    }
}
