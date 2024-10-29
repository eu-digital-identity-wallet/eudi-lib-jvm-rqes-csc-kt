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

import eu.europa.ec.eudi.rqes.*
import eu.europa.ec.eudi.rqes.internal.http.SignHashEndpointClient

internal class SignHashImpl(
    private val signHashEndpointClient: SignHashEndpointClient,
) : SignHash {

    override suspend fun CredentialAuthorized.signHash(
        signingAlgorithmOID: SigningAlgorithmOID,
    ): Result<SignaturesList> = runCatching {
        signHashEndpointClient.signHashes(
            credentialID,
            documentDigestList.documentDigests.map(DocumentDigest::hash).map { it.value },
            documentDigestList.hashAlgorithmOID,
            signingAlgorithmOID,
            tokens.accessToken,
        )
    }
}
