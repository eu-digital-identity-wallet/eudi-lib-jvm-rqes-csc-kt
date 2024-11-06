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
import eu.europa.ec.eudi.rqes.internal.http.SCACalculateHashEndpointClient

internal class CalculateDocumentHashesImpl(
    private val scaCalculateHashEndpointClient: SCACalculateHashEndpointClient,
) : CalculateDocumentHashes {
    override suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID: HashAlgorithmOID,
    ): DocumentDigestList {
        val hashesResponse =
            scaCalculateHashEndpointClient.calculateHash(documents, credentialCertificate, hashAlgorithmOID)
        documents.zip(hashesResponse.hashes).map {
            DocumentDigest(Digest(it.second), it.first.file.label)
        }.let {
            return DocumentDigestList(it, hashAlgorithmOID, hashesResponse.signatureDate)
        }
    }
}
