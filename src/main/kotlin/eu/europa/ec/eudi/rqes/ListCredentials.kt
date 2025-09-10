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
package eu.europa.ec.eudi.rqes

import eu.europa.ec.eudi.rqes.internal.http.CredentialsListEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.CredentialsListTO
import eu.europa.ec.eudi.rqes.internal.http.ListCredentialInfoTO.Companion.toDomain

data class CredentialsListRequest(
    val credentialInfo: Boolean? = true,
    val certificates: Certificates? = Certificates.Chain,
    val certInfo: Boolean? = true,
    val authInfo: Boolean? = true,
    val onlyValid: Boolean? = true,
    val lang: String? = null,
    val clientData: String? = null,
)

fun interface ListCredentials {

    suspend fun ServiceAccessAuthorized.listCredentials(
        request: CredentialsListRequest,
    ): Result<List<CredentialInfo>>

    companion object {
        internal operator fun invoke(credentialsListEndpointClient: CredentialsListEndpointClient): ListCredentials =
            ListCredentials { request ->
                runCatching {
                    val credentialsList = credentialsListEndpointClient.listCredentials(
                        request,
                        tokens.accessToken,
                    ).getOrThrow()

                    when (credentialsList) {
                        is CredentialsListTO.Success -> credentialsList.credentialInfos?.map { it.toDomain() }
                            ?: emptyList()

                        else -> error("Unexpected response: $credentialsList")
                    }
                }
            }
    }
}
