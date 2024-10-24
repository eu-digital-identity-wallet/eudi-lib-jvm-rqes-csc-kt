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

import eu.europa.ec.eudi.rqes.internal.AuthorizeCredentialImpl
import eu.europa.ec.eudi.rqes.internal.AuthorizeServiceImpl
import eu.europa.ec.eudi.rqes.internal.SignDocImpl
import eu.europa.ec.eudi.rqes.internal.SignHashImpl
import eu.europa.ec.eudi.rqes.internal.http.*
import eu.europa.ec.eudi.rqes.internal.http.AuthorizationEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.CredentialsListEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.SCACalculateHashEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.SCAObtainSignedDocEndpointClient
import eu.europa.ec.eudi.rqes.internal.http.TokenEndpointClient

interface CSCClient :
    AuthorizeService,
    AuthorizeCredential,
    ListCredentials,
    SignHash,
    SignDoc {

    val rsspMetadata: RSSPMetadata

    companion object {
        suspend fun oauth2(
            cscClientConfig: CSCClientConfig,
            rsspId: String,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<CSCClient> = kotlin.runCatching {
            val metadata =
                run {
                    val id = RSSPId(rsspId).getOrThrow()
                    val resolver = RSSPMetadataResolver(ktorHttpClientFactory)
                    resolver.resolve(id, cscClientConfig.locale).getOrThrow()
                }
            oauth2(cscClientConfig, metadata, ktorHttpClientFactory).getOrThrow()
        }

        fun oauth2(
            cscClientConfig: CSCClientConfig,
            rsspMetadata: RSSPMetadata,
            ktorHttpClientFactory: KtorHttpClientFactory = DefaultHttpClientFactory,
        ): Result<CSCClient> = runCatching {
            val oauth2AuthType =
                requireNotNull(rsspMetadata.oauth2AuthType()) { "RSSP doesn't support OAUTH2" }
            val (authServerMetadata, grants) = oauth2AuthType

            val tokenEndpointClient = TokenEndpointClient(
                checkNotNull(authServerMetadata.tokenEndpointURI).toURL(),
                cscClientConfig,
                ktorHttpClientFactory,
            )

            val authorizationEndpointClient =
                if (Oauth2Grant.AuthorizationCode in grants) {
                    AuthorizationEndpointClient(
                        checkNotNull(authServerMetadata.authorizationEndpointURI).toURL(),
                        authServerMetadata.pushedAuthorizationRequestEndpointURI?.toURL(),
                        cscClientConfig,
                        ktorHttpClientFactory,
                    )
                } else null

            val authorizeServiceImpl = AuthorizeServiceImpl(
                authorizationEndpointClient,
                tokenEndpointClient,
            )

            val scaCalculateHashEndpointClient =
                SCACalculateHashEndpointClient(
                    cscClientConfig.scaBaseURL,
                    ktorHttpClientFactory,
                )

            val authorizeCredentialImpl = AuthorizeCredentialImpl(
                authorizationEndpointClient,
                tokenEndpointClient,
                scaCalculateHashEndpointClient,
            )

            val credentialsListEndpointClient =
                CredentialsListEndpointClient(
                    rsspMetadata.rsspId.value.value,
                    ktorHttpClientFactory,
                )

            val listCredentialsImpl = ListCredentials(credentialsListEndpointClient)

            val signHashEndpointClient = SignHashEndpointClient(
                rsspMetadata.rsspId.value.value,
                ktorHttpClientFactory,
            )

            val signHashImpl = SignHashImpl(
                signHashEndpointClient,
            )

            val scaObtainSignedDocEndpointClient =
                SCAObtainSignedDocEndpointClient(
                    cscClientConfig.scaBaseURL,
                    ktorHttpClientFactory,
                )

            val signDocImpl = SignDocImpl(
                signHashEndpointClient,
                scaObtainSignedDocEndpointClient,
            )

            object :
                CSCClient,
                AuthorizeService by authorizeServiceImpl,
                AuthorizeCredential by authorizeCredentialImpl,
                ListCredentials by listCredentialsImpl,
                SignHash by signHashImpl,
                SignDoc by signDocImpl {
                override val rsspMetadata: RSSPMetadata = rsspMetadata
            }
        }
    }
}
