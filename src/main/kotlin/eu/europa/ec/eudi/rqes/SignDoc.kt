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

import java.time.Clock

data class SignDocResponse(
    val documentWithSignature: List<String>,
    val signatureObject: List<String>,
    val validationInfo: ValidationInfo?,
)

data class ValidationInfo(
    val ocsp: List<String>,
    val crl: List<String>,
    val certificate: List<String>,
)

interface SignDoc {

    suspend fun CredentialAuthorized.signDoc(
        documents: List<DocumentToSign>,
        signingAlgorithmOID: SigningAlgorithmOID
    ): Result<SignDocResponse>
}
