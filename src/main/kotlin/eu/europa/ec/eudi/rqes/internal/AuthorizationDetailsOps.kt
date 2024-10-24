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

import com.nimbusds.oauth2.sdk.rar.AuthorizationType
import eu.europa.ec.eudi.rqes.AuthorizationDetails
import eu.europa.ec.eudi.rqes.CredentialRef
import eu.europa.ec.eudi.rqes.Scope
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray

internal fun AuthorizationDetails.toNimbusAuthDetail(): com.nimbusds.oauth2.sdk.rar.AuthorizationDetail =
    com.nimbusds.oauth2.sdk.rar.AuthorizationDetail.Builder(AuthorizationType(Scope.Credential.value)).apply {
        when (credentialRef) {
            is CredentialRef.ByCredentialID -> field("credentialID", credentialRef.credentialID)
            is CredentialRef.BySignatureQualifier -> field("signatureQualifier", credentialRef.signatureQualifier)
        }
        documentDigestList?.let {
            buildJsonArray {
                documentDigestList.documentDigests.map {
                    addJsonObject {
                        put("hash", JsonPrimitive(it.hash.value))
                        put("label", JsonPrimitive(it.label))
                    }
                }
            }
            field("hashAlgorithmOID", it.hashAlgorithmOID.value)
        }
        locations?.let { field("locations", it) }
    }.build()
