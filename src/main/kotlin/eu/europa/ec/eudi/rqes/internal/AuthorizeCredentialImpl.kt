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
package eu.europa.ec.eudi.rqes.internal

import com.nimbusds.oauth2.sdk.id.State
import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.AuthorizationError.InvalidAuthorizationState
import eu.europa.ec.eudi.rqes.internal.http.*
import eu.europa.ec.eudi.rqes.internal.http.CredentialInfoTO.Success.Companion.toDomain

internal class AuthorizeCredentialImpl(
    private val authorizationEndpointClient: AuthorizationEndpointClient?,
    private val tokenEndpointClient: TokenEndpointClient,
    private val credentialsInfoEndpointClient: CredentialsInfoEndpointClient,
    private val scaCalculateHashEndpointClient: SCACalculateHashEndpointClient?,
) : AuthorizeCredential {

    override suspend fun ServiceAccessAuthorized.prepareCredentialAuthorizationRequest(
        credentialID: CredentialID,
        documents: List<DocumentToSign>?,
        numSignatures: Int?,
        walletState: String?,
    ): Result<CredentialAuthorizationRequestPrepared> = runCatching {
        checkNotNull(authorizationEndpointClient)

        val credential = getCredentialInfo(credentialID, tokens.accessToken)

        val documentDigestList = if (credential.scal == SCAL.Two) {
            require(documents != null) { "Document list is required for SCAL 2" }
            calculateDocumentHash(documents, credential, HashAlgorithmOID.SHA_256)
        } else null

        val scopes = listOf(Scope(Scope.Credential.value))
        val state = walletState ?: State().value
        val authorizationDetails = AuthorizationDetails(
            CredentialRef.ByCredentialID(credentialID),
            numSignatures,
            documentDigestList,
        )
        val (codeVerifier, authorizationCodeUrl) = authorizationEndpointClient.submitParOrCreateAuthorizationRequestUrl(
            scopes,
            authorizationDetails,
            state,
        ).getOrThrow()
        CredentialAuthorizationRequestPrepared(
            AuthorizationRequestPrepared(authorizationCodeUrl, codeVerifier, state),
            credential,
            authorizationDetails,
        )
    }

    private suspend fun getCredentialInfo(credentialID: CredentialID, accessToken: AccessToken): CredentialInfo {
        val credentialInfoTO = credentialsInfoEndpointClient.credentialInfo(
            CredentialsInfoRequest(credentialID),
            accessToken,
        ).getOrThrow()

        return when (credentialInfoTO) {
            is CredentialInfoTO.Success -> {
                credentialInfoTO.toDomain(credentialID)
            }

            else -> throw IllegalStateException("Unexpected response: $credentialInfoTO")
        }
    }

    private suspend fun calculateDocumentHash(
        documents: List<DocumentToSign>,
        credential: CredentialInfo,
        hashAlgorithmOID: HashAlgorithmOID,
    ): DocumentDigestList {
        requireNotNull(scaCalculateHashEndpointClient) {
            "SCA Calculate Hash Endpoint Client is required hash calculation"
        }
        val hashesResponse =
            scaCalculateHashEndpointClient.calculateHash(documents, credential.certificate, hashAlgorithmOID)
        documents.zip(hashesResponse.hashes).map {
            DocumentDigest(Digest(it.second), it.first.file.label)
        }.let {
            return DocumentDigestList(it, hashAlgorithmOID, hashesResponse.signatureDate)
        }
    }

    override suspend fun CredentialAuthorizationRequestPrepared.authorizeWithAuthorizationCode(
        authorizationCode: AuthorizationCode,
        serverState: String,
        authDetailsOption: AccessTokenOption,
    ): Result<CredentialAuthorized> = runCatching {
        ensure(serverState == value.state) { InvalidAuthorizationState() }

        val tokenResponse =
            tokenEndpointClient.requestAccessTokenAuthFlow(authorizationCode, value.pkceVerifier, authorizationDetails)

        val (accessToken, refreshToken, timestamp) = tokenResponse.getOrThrow()

        if (credential.scal == SCAL.One) {
            CredentialAuthorized.SCAL1(
                OAuth2Tokens(accessToken, refreshToken, timestamp),
                credential.credentialID,
                credential.certificate,
            )
        } else {
            requireNotNull(authorizationDetails.documentDigestList) {
                "Document list is required for SCAL 2"
            }
            CredentialAuthorized.SCAL2(
                OAuth2Tokens(accessToken, refreshToken, timestamp),
                credential.credentialID,
                credential.certificate,
                authorizationDetails.documentDigestList,
            )
        }
    }
}
