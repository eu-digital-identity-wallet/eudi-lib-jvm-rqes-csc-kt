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
package eu.europa.ec.eudi.rqes.internal.http

import eu.europa.ec.eudi.rqes.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.URL
import java.time.Instant
import java.util.*

internal data class CalculateHashResponse(
    val hashes: List<String>,
    val signatureDate: Instant,
)

@Serializable
internal data class CalculateHashRequestTO(
    @SerialName("documents") val documents: List<DocumentToSignTO>,
    @SerialName("endEntityCertificate") val endEntityCertificate: String,
    @SerialName("certificateChain") val certificateChain: List<String>? = null,
    @SerialName("hashAlgorithmOID") val hashAlgorithmOID: String,
)

@Serializable
internal data class DocumentToSignTO(
    @SerialName("document") @Required val document: String,
    @SerialName("signature_format") @Required val signatureFormat: SignatureFormat,
    @SerialName("conformance_level") @Required val conformanceLevel: ConformanceLevel,
    @SerialName("signed_envelope_property") @Required val signedEnvelopeProperty: SignedEnvelopeProperty,
    @SerialName("container") @Required val asicContainer: ASICContainer,
)

internal sealed interface CalculateHashResponseTO {

    @Serializable
    data class Success(
        @SerialName("hashes") val hashes: List<String>,
        @SerialName("signature_date") val signatureDate: Long,
    ) : CalculateHashResponseTO

    @Serializable
    data class Failure(
        @SerialName("error") val error: String,
        @SerialName("error_description") val errorDescription: String? = null,
    ) : CalculateHashResponseTO

    fun getOrFail(): CalculateHashResponse =
        when (this) {
            is Success -> CalculateHashResponse(hashes, Instant.ofEpochMilli(signatureDate))
            is Failure -> throw RuntimeException("Error: $error, $errorDescription")
        }
}

internal class SCACalculateHashEndpointClient(
    private val scaBaseURL: URL,
    private val ktorHttpClientFactory: KtorHttpClientFactory,
) {
    suspend fun calculateHash(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
    ): CalculateHashResponse =
        ktorHttpClientFactory().use { client ->
            val response = client.get("$scaBaseURL/signatures/calculate_hash") {
                contentType(ContentType.Application.Json)
                setBody(
                    CalculateHashRequestTO(
                        documents = documents.map {
                            DocumentToSignTO(
                                document = it.file.content.toBase64(),
                                signatureFormat = it.signatureFormat,
                                conformanceLevel = it.conformanceLevel,
                                signedEnvelopeProperty = it.signedEnvelopeProperty,
                                asicContainer = it.asicContainer,
                            )
                        },
                        endEntityCertificate = credentialCertificate.certificates?.first().toString(),
                        certificateChain = credentialCertificate.certificates?.drop(1)?.map { it.toString() }
                            ?: emptyList(),
                        hashAlgorithmOID = hashAlgorithmOID.value,
                    ),
                )
            }
            if (response.status.isSuccess()) {
                response.body<CalculateHashResponseTO.Success>()
            } else {
                response.body<CalculateHashResponseTO.Failure>()
            }
        }.getOrFail()
}

internal fun InputStream.toBase64(): String {
    val buffer = ByteArray(8192) // 8KB buffer
    val outputStream = ByteArrayOutputStream()
    val base64Encoder = Base64.getEncoder().wrap(outputStream)

    var bytesRead: Int
    while (this.read(buffer).also { bytesRead = it } != -1) {
        base64Encoder.write(buffer, 0, bytesRead)
    }

    base64Encoder.close()
    return outputStream.toString("UTF-8")
}
