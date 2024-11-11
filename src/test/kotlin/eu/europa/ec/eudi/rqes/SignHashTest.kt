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

import kotlinx.coroutines.test.runTest
import java.time.Instant
import kotlin.test.*

class SignHashTest {

    @Test
    fun `successful hash signing with a SCAL1 credential`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            signHashPostMocker(),
        )

        val signatures = with(mockPublicClient(mockedKtorHttpClientFactory)) {
            val credential = with(mockServiceAccessAuthorized) {
                credentialInfo(CredentialsInfoRequest(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81"))).getOrThrow()
            }

            val documentDigestList = DocumentDigestList(
                hashAlgorithmOID = HashAlgorithmOID.SHA_256,
                hashCalculationTime = Instant.ofEpochMilli(1731313375117),
                documentDigests = listOf(
                    DocumentDigest(
                        hash = Digest("MYIBAzAYBgkqhkiG9w0BCQMxCwYJKoZIhvc"),
                        label = "Test document",
                    ),
                ),
            )

            with(mockCredentialAuthorizedSCAL1(credential, documentDigestList)) {
                signHash(documentDigestList, SigningAlgorithmOID.RSA).getOrThrow()
            }
        }

        assertNotNull(signatures)
    }

    @Test
    fun `successful hash signing with a SCAL2 credential`() = runTest {
        val mockedKtorHttpClientFactory = mockedKtorHttpClientFactory(
            authServerWellKnownMocker(),
            credentialsInfoPostMocker(),
            signHashPostMocker(),
        )

        val signatures = with(mockPublicClient(mockedKtorHttpClientFactory)) {
            val credential = with(mockServiceAccessAuthorized) {
                credentialInfo(CredentialsInfoRequest(CredentialID("83c7c559-db74-48da-aacc-d439d415cb81"))).getOrThrow()
            }

            val documentDigestList = DocumentDigestList(
                hashAlgorithmOID = HashAlgorithmOID.SHA_256,
                hashCalculationTime = Instant.ofEpochMilli(1731313375117),
                documentDigests = listOf(
                    DocumentDigest(
                        hash = Digest("MYIBAzAYBgkqhkiG9w0BCQMxCwYJKoZIhvc"),
                        label = "Test document",
                    ),
                ),
            )

            with(mockCredentialAuthorizedSCAL2(credential, documentDigestList)) {
                signHash(SigningAlgorithmOID.RSA).getOrThrow()
            }
        }

        assertNotNull(signatures)
    }
}
