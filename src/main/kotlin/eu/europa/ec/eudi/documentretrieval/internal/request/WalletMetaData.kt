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
package eu.europa.ec.eudi.documentretrieval.internal.request

import eu.europa.ec.eudi.documentretrieval.DocumentRetrievalConfig
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray

private const val REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED = "request_object_signing_alg_values_supported"
private const val RESPONSE_MODES_SUPPORTED = "response_modes_supported"

internal fun walletMetaData(cfg: DocumentRetrievalConfig): JsonObject =
    buildJsonObject {
        //
        // JAR related
        //
        putJsonArray(REQUEST_OBJECT_SIGNING_ALG_VALUES_SUPPORTED) {
            cfg.jarConfiguration.supportedAlgorithms.forEach { alg -> add(alg.name) }
        }

        putJsonArray(RESPONSE_MODES_SUPPORTED) {
            add("direct_post")
        }
    }
