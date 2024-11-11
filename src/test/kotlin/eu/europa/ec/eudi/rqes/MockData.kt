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

import eu.europa.ec.eudi.rqes.internal.asMetadata
import io.ktor.http.*
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.*

object SampleRSSP {
    val Id: RSSPId = RSSPId("https://rssp.example.com/csc/v2").getOrThrow()
}

internal fun mockPublicClient(
    ktorHttpClientFactory: KtorHttpClientFactory,
    parUsage: ParUsage = ParUsage.Never,
    rarUsage: RarUsage = RarUsage.IfSupported,
) =
    mockClient(
        OAuth2Client.Public("client-id"),
        ktorHttpClientFactory,
        parUsage,
        rarUsage,
    )

internal fun mockConfidentialClient(
    ktorHttpClientFactory: KtorHttpClientFactory,
    parUsage: ParUsage = ParUsage.Never,
    rarUsage: RarUsage = RarUsage.IfSupported,
) = mockClient(
    OAuth2Client.Confidential.ClientSecretPost("client-id", "secret"),
    ktorHttpClientFactory,
    parUsage,
    rarUsage,
)

private fun mockClient(
    oauth2Client: OAuth2Client,
    ktorHttpClientFactory: KtorHttpClientFactory,
    parUsage: ParUsage = ParUsage.Never,
    rarUsage: RarUsage = RarUsage.IfSupported,
) = CSCClient.oauth2(
    rsspMetadata = rsspMetadata(),
    cscClientConfig = CSCClientConfig(
        oauth2Client,
        URI("https://example.com/redirect"),
        URI("https://walletcentric.signer.eudiw.dev").toURL(),
        parUsage,
        rarUsage,
    ),
    ktorHttpClientFactory = ktorHttpClientFactory,
).getOrThrow()

internal fun RSSPId.info() = HttpsUrl(
    URLBuilder(toString()).appendPathSegments("/info", encodeSlash = false).buildString(),
).getOrThrow()

/**
 * Gets the [RSSPMetadata] used throughout the tests.
 */
internal fun rsspMetadata() = RSSPMetadata(
    rsspId = SampleRSSP.Id,
    specs = "2.0.0.0",
    name = "ACME Trust Services",
    logo = URI("https://service.domain.org/images/logo.png"),
    region = "IT",
    lang = Locale.forLanguageTag("en-US"),
    description = "An efficient remote signature service",
    authTypes = setOf(
        AuthType.Basic,
        AuthType.OAuth2(authorizationServerMetadata, setOf(Oauth2Grant.AuthorizationCode)),
    ),

    methods = methods,
)

internal fun rsspMetadataWithOAuth2Issuer() = RSSPMetadata(
    rsspId = SampleRSSP.Id,
    specs = "2.0.0.0",
    name = "ACME Trust Services",
    logo = URI("https://service.domain.org/images/logo.png"),
    region = "IT",
    lang = Locale.forLanguageTag("en-US"),
    description = "An efficient remote signature service",
    authTypes = setOf(
        AuthType.Basic,
        AuthType.OAuth2(authorizationServerMetadata, setOf(Oauth2Grant.AuthorizationCode)),
    ),

    methods = methods,
)

internal fun RSSPMetadata.withClientCredentialsFlow() = run {
    copy(authTypes = setOf(AuthType.OAuth2(authorizationServerMetadata, setOf(Oauth2Grant.ClientCredentials))))
}

private val methods = listOf(
    RSSPMethod.AuthLogin,
    RSSPMethod.AuthRevoke,
    RSSPMethod.CredentialsList,
    RSSPMethod.CredentialsInfo,
    RSSPMethod.CredentialsAuthorize,
    RSSPMethod.CredentialsSendOTP,
    RSSPMethod.SignaturesSignHash,
    RSSPMethod.Oauth2Authorize,
    RSSPMethod.Oauth2Token,
    RSSPMethod.Oauth2PushedAuthorize,
)

private val authorizationServerMetadata =
    asMetadata(HttpsUrl("https://auth.domain.org").getOrThrow(), methods)

internal val mockServiceAccessAuthorized = ServiceAccessAuthorized(
    OAuth2Tokens(
        accessToken = AccessToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        RefreshToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        timestamp = Instant.now(),
    ),
)

internal fun mockCredentialAuthorizedSCAL1(
    credentialInfo: CredentialInfo,
    documentDigestList: DocumentDigestList,
) = CredentialAuthorized.SCAL1(
    OAuth2Tokens(
        accessToken = AccessToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        RefreshToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        timestamp = Instant.now(),
    ),
    credentialInfo.credentialID,
    credentialInfo.certificate,
)

internal fun mockCredentialAuthorizedSCAL2(
    credentialInfo: CredentialInfo,
    documentDigestList: DocumentDigestList,
) = CredentialAuthorized.SCAL2(
    OAuth2Tokens(
        accessToken = AccessToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        RefreshToken(UUID.randomUUID().toString(), Duration.ofSeconds(600)),
        timestamp = Instant.now(),
    ),
    credentialInfo.credentialID,
    credentialInfo.certificate,
    documentDigestList,
)
