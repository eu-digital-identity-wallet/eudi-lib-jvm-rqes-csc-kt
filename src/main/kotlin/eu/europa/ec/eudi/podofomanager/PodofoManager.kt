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
package eu.europa.ec.eudi.podofomanager

import android.R.string
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.podofo.android.PoDoFoWrapper
import eu.europa.ec.eudi.rqes.ConformanceLevel
import eu.europa.ec.eudi.rqes.CredentialCertificate
import eu.europa.ec.eudi.rqes.Digest
import eu.europa.ec.eudi.rqes.DocumentDigest
import eu.europa.ec.eudi.rqes.DocumentDigestList
import eu.europa.ec.eudi.rqes.DocumentToSign
import eu.europa.ec.eudi.rqes.HashAlgorithmOID
import eu.europa.ec.eudi.rqes.OcspRequest
import eu.europa.ec.eudi.rqes.TimestampRequestTO
import eu.europa.ec.eudi.rqes.TimestampResponseTO
import eu.europa.ec.eudi.rqes.TimestampServiceImpl
import eu.europa.ec.eudi.rqes.CrlRequest
import eu.europa.ec.eudi.rqes.RevocationServiceImpl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant


class PodofoManager {
    private var podofoSessions by mutableStateOf<List<PodofoSession>>(emptyList())

    public suspend fun calculateDocumentHashes(
        documents: List<DocumentToSign>,
        credentialCertificate: CredentialCertificate,
        hashAlgorithmOID : HashAlgorithmOID,
        tsaUrl: String
    ): DocumentDigestList {
        try {
            podofoSessions = emptyList()
            val endEntityCertificate = credentialCertificate.rawCertificates.first()
            val certificateChain = credentialCertificate.rawCertificates.drop(1)

            val hashes = mutableListOf<String>()
            var c = 1

            validateTsaUrlRequirement(documents, tsaUrl)

            for (doc in documents) {
                try {
                    val podofoWrapper = PoDoFoWrapper(
                        doc.conformanceLevel.name,
                        hashAlgorithmOID.value,
                        doc.documentInputPath,
                        doc.documentOutputPath,
                        endEntityCertificate,
                        certificateChain.toTypedArray()
                    )

                    val session = PodofoSession(
                        id = c.toString(),
                        session = podofoWrapper,
                        conformanceLevel = doc.conformanceLevel,
                        endCertificate = endEntityCertificate,
                        chainCertificates = certificateChain
                    )
                    c++

                    podofoWrapper.calculateHash()?.let { hash ->
                        hashes += hash
                        podofoSessions = podofoSessions + session
                    } ?: throw IllegalStateException("Failed to calculate hash for document: ${doc.documentInputPath}")

                } catch (e: Exception) {
                    println("Failed to calculate hash for ${doc.documentOutputPath}")
                }
            }

            if (hashes.size != documents.size) {
                error("Internal error: got ${hashes.size} hashes for ${documents.size} documents")
            }

            val digestEntries = hashes.mapIndexed { idx, rawHash ->
                DocumentDigest(
                    hash  = Digest(rawHash),
                    label = documents[idx].label
                )
            }

            return DocumentDigestList(
                documentDigests     = digestEntries,
                hashAlgorithmOID    = HashAlgorithmOID(hashAlgorithmOID.value),
                hashCalculationTime = Instant.now()
            )
        } catch (e: Exception) {
            println("Error in calculateDocumentHashes for ${documents.map { it.label }}")
            throw e
        }
    }

    public suspend fun createSignedDocuments(signatures: List<String>, tsaUrl: String?) = withContext(Dispatchers.IO) {
        println("Starting to create signed documents...")
        try {
            if (signatures.size != podofoSessions.size) {
                throw IllegalArgumentException("Signatures count (${signatures.size}) does not match session count (${podofoSessions.size})")
            }

            podofoSessions.forEachIndexed { index, sessionWrapper ->
                val signedHash = signatures[index]
                println("Processing session ${sessionWrapper.id} for conformance level ${sessionWrapper.conformanceLevel}")
                sessionWrapper.session.printState()

                when (sessionWrapper.conformanceLevel) {
                    ConformanceLevel.ADES_B_B -> {
                        handleAdesB_B(sessionWrapper, signedHash)
                    }
                    ConformanceLevel.ADES_B_T -> {
                        require(!tsaUrl.isNullOrEmpty()) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_T(sessionWrapper, signedHash, tsaUrl)
                    }
                    ConformanceLevel.ADES_B_LT -> {
                        require(!tsaUrl.isNullOrEmpty()) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_LT(sessionWrapper, signedHash, tsaUrl)
                    }
                    ConformanceLevel.ADES_B_LTA -> {
                        require(!tsaUrl.isNullOrEmpty()) { "Missing TSA URL for conformance level: ${sessionWrapper.conformanceLevel.name}" }
                        handleAdesB_LTA(sessionWrapper, signedHash, tsaUrl)
                    }
                    else -> throw IllegalArgumentException("Unknown or unsupported conformance level")
                }
            }


        }
        finally {
            podofoSessions = emptyList()
        }
    }

    private fun handleAdesB_B(sessionWrapper: PodofoSession, signedHash: String) {
        println("Handling ADES-B-B...")
        println("Signed hash: $signedHash")
        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            "",
            mutableListOf(),
            mutableListOf(),
            mutableListOf()
        )
    }

    private suspend fun handleAdesB_T(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        println("Handling ADES-B-T...")
        println("Signed hash: $signedHash, TSA URL: $tsaUrl")
        val response = requestTimestamp(signedHash, tsaUrl)
        println("Timestamp response (TSR): ${response.base64Tsr}")

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            response.base64Tsr,
            mutableListOf(),
            mutableListOf(),
            mutableListOf()
        )
    }

    private suspend fun handleAdesB_LT(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        println("Handling ADES-B-LT...")
        val timestampAndRevocationData = addTimestampAndRevocationInfo(
            sessionWrapper,
            signedHash,
            tsaUrl
        )
        println("Timestamp and revocation data fetched for LT: $timestampAndRevocationData")

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            timestampAndRevocationData.tsResponse.base64Tsr,
            timestampAndRevocationData.validationCertificates,
            timestampAndRevocationData.validationCrls,
            timestampAndRevocationData.validationOCSPs
        )
    }

    private suspend fun handleAdesB_LTA(sessionWrapper: PodofoSession, signedHash: String, tsaUrl: String) {
        println("Handling ADES-B-LTA...")
        val timestampAndRevocationData = addTimestampAndRevocationInfo(
            sessionWrapper,
            signedHash,
            tsaUrl
        )
        println("Timestamp and revocation data fetched for LTA (initial step): $timestampAndRevocationData")

        sessionWrapper.session.finalizeSigningWithSignedHash(
            signedHash,
            timestampAndRevocationData.tsResponse.base64Tsr,
            timestampAndRevocationData.validationCertificates,
            timestampAndRevocationData.validationCrls,
            timestampAndRevocationData.validationOCSPs
        )

        val ltaRawHash = sessionWrapper.session.beginSigningLTA()
        if (ltaRawHash != null) {
            println("LTA raw hash for document timestamp: $ltaRawHash")
            val tsLtaResponse = requestDocTimestamp(ltaRawHash, tsaUrl)
            println("LTA document timestamp response: ${tsLtaResponse.base64Tsr}")

            val validationLTACertificates: MutableList<String> = mutableListOf()
            val validationLTACrls: MutableList<String> = mutableListOf()
            val validationLTAOCSPs: MutableList<String> = mutableListOf()

            try {
                println("Fetching LTA OCSP response...")
                val base64LTAOcspResponse = fetchOcspResponse(
                    sessionWrapper,
                    tsLtaResponse.base64Tsr
                )
                println("LTA OCSP response: $base64LTAOcspResponse")
                validationLTAOCSPs.add(base64LTAOcspResponse)

                println("Extracting LTA signer and issuer certificates from TSR...")
                val tsaLTASignerCert =
                    sessionWrapper.session.extractSignerCertFromTSR(tsLtaResponse.base64Tsr)
                validationLTACertificates.add(tsaLTASignerCert)
                println("LTA TSA Signer Cert: $tsaLTASignerCert")

                val tsaLTAIssuerCert =
                    sessionWrapper.session.extractIssuerCertFromTSR(tsLtaResponse.base64Tsr)
                validationLTACertificates.add(tsaLTAIssuerCert)
                println("LTA TSA Issuer Cert: $tsaLTAIssuerCert")

                println("Fetching LTA CRLs...")
                val crlLTAUrls = mutableSetOf<String>()
                sessionWrapper.session.getCrlFromCertificate(tsaLTASignerCert)
                    ?.let { crlSignerLTAUrl ->
                        crlLTAUrls.add(crlSignerLTAUrl)
                    }
                val crls = fetchCrlDataFromUrls(crlLTAUrls.toList())
                validationLTACrls.addAll(crls)
                println("LTA CRLs fetched: $crls")

            } catch (e: Exception) {
                println("No OCSPs were found for LTA: ${e.message}")
            }
            println("Finishing LTA signing...")
            sessionWrapper.session.finishSigningLTA(
                tsLtaResponse.base64Tsr,
                validationLTACertificates,
                validationLTACrls,
                validationLTAOCSPs
            )
        } else {
            println("Failed to begin LTA signing, hash was null.")
        }
    }

    private data class TimestampAndRevocationData(
        val tsResponse: TimestampResponseTO,
        val validationCertificates: List<String>,
        val validationCrls: List<String>,
        val validationOCSPs: List<String>
    )

    private suspend fun addTimestampAndRevocationInfo(
        sessionWrapper: PodofoSession,
        signedHash: String,
        tsaUrl: String
    ): TimestampAndRevocationData {
        println("Adding timestamp and revocation info...")
        println("Requesting timestamp for hash: $signedHash")
        val tsResponse = requestTimestamp(signedHash, tsaUrl)
        println("Timestamp received: ${tsResponse.base64Tsr}")

        val validationCertificates = prepareValidationCertificates(
            sessionWrapper,
            tsResponse.base64Tsr
        )

        val certificatesForCrlExtraction = listOf(sessionWrapper.endCertificate) + sessionWrapper.chainCertificates
        val crlUrls = mutableSetOf<String>()

        println("Extracting CRL URLs from certificates...")
        for (certificate in certificatesForCrlExtraction) {
            sessionWrapper.session.getCrlFromCertificate(certificate)?.let { crlUrl ->
                crlUrls.add(crlUrl)
                println("Found CRL URL: $crlUrl")
            }
        }

        println("Fetching CRL data...")
        val validationCrls = fetchCrlDataFromUrls(crlUrls.toList())
        println("CRL data fetched: $validationCrls")
        val validationOCSPs = mutableListOf<String>()

        try {
            println("Fetching OCSP response...")
            val ocspResponse = fetchOcspResponse(
                sessionWrapper,
                tsResponse.base64Tsr
            )
            validationOCSPs.add(ocspResponse)
            println("OCSP response received: $ocspResponse")
        } catch (e: Exception) {
            println("No OCSPs were found: ${e.message}")
        }

        val result = TimestampAndRevocationData(tsResponse, validationCertificates, validationCrls, validationOCSPs)
        println("Finished adding timestamp and revocation info. Result: $result")
        return result
    }

    private suspend fun fetchOcspResponse(sessionWrapper: PodofoSession, tsr: String): String {
        println("Fetching OCSP response for TSR: $tsr")
        var ocspUrl: String
        var base64OcspRequest: String

        try {
            println("Attempting to get OCSP data using primary method...")
            val tsaSignerCert = sessionWrapper.session.extractSignerCertFromTSR(tsr)
            val tsaIssuerCert = sessionWrapper.session.extractIssuerCertFromTSR(tsr)
            println("Signer Cert: $tsaSignerCert, Issuer Cert: $tsaIssuerCert")
            ocspUrl = sessionWrapper.session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert)
            base64OcspRequest = sessionWrapper.session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert)
            println("OCSP URL: $ocspUrl, OCSP Request: $base64OcspRequest")
        } catch (e: Exception) {
            println("Primary OCSP method failed: ${e.message}. Trying fallback...")
            try {
                val tsaSignerCert = sessionWrapper.session.extractSignerCertFromTSR(tsr)
                val issuerUrl = sessionWrapper.session.getCertificateIssuerUrlFromCertificate(tsaSignerCert)
                println("Fallback: Fetched issuer URL: $issuerUrl")
                val tsaIssuerCert = fetchCertificateFromUrl(issuerUrl)
                println("Fallback: Fetched issuer certificate: $tsaIssuerCert")
                ocspUrl = sessionWrapper.session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert)
                base64OcspRequest = sessionWrapper.session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert)
                println("Fallback: OCSP URL: $ocspUrl, OCSP Request: $base64OcspRequest")
            } catch (fallbackError: Exception) {
                println("OCSP fallback method also failed: ${fallbackError.message}")
                throw Exception("Failed to fetch OCSP response: Primary error: ${e.message}, Fallback error: ${fallbackError.message}")
            }
        }

        println("Making OCSP HTTP POST request to $ocspUrl")
        return makeOcspHttpPostRequest(ocspUrl, base64OcspRequest)
    }

    private suspend fun requestTimestamp(hash: String, tsaUrl: String): TimestampResponseTO {
        val tsService = TimestampServiceImpl()
        val tsRequest = TimestampRequestTO(
            signedHash = hash,
            tsaUrl = tsaUrl
        )
        return tsService.requestTimestamp(tsRequest)
    }

    private suspend fun requestDocTimestamp(hash: String, tsaUrl: String): TimestampResponseTO {
        val tsService = TimestampServiceImpl()
        val tsRequest = TimestampRequestTO(
            signedHash = hash,
            tsaUrl = tsaUrl
        )
        return tsService.requestDocTimestamp(tsRequest)
    }

    private fun prepareValidationCertificates(sessionWrapper: PodofoSession, timestampResponse: String): List<String> {
        return listOf(sessionWrapper.endCertificate) + sessionWrapper.chainCertificates + timestampResponse
    }

    private suspend fun fetchCrlDataFromUrls(crlUrls: List<String>): List<String> {
        println("Fetching CRL data from URLs: $crlUrls")
        val validationCrlResponses = mutableListOf<String>()
        val revocationService = RevocationServiceImpl()

        for (crlUrl in crlUrls) {
            println("Fetching CRL from: $crlUrl")
            val crlRequest = CrlRequest(crlUrl = crlUrl)
            val crlInfo = revocationService.getCrlData(request = crlRequest)
            validationCrlResponses.add(crlInfo.crlInfoBase64)
            println("Successfully fetched CRL from $crlUrl")
        }
        return validationCrlResponses
    }

    private suspend fun fetchCertificateFromUrl(url: String): String {
        println("Fetching certificate from URL: $url")
        val revocationService = RevocationServiceImpl()
        val request = eu.europa.ec.eudi.rqes.CertificateRequest(certificateUrl = url)
        val response = revocationService.getCertificateData(request)
        println("Successfully fetched certificate from $url")
        return response.certificateBase64
    }

    private suspend fun makeOcspHttpPostRequest(url: String, request: String): String {
        println("Making OCSP POST request to $url")
        val revocationService = RevocationServiceImpl()
        val ocspRequest = OcspRequest(ocspUrl = url, ocspRequest = request)
        val response = revocationService.getOcspData(ocspRequest)
        println("Successfully received OCSP response from $url")
        return response.ocspInfoBase64
    }

    private fun validateTsaUrlRequirement(docs: List<DocumentToSign>, tsaUrl: String) {
        for (doc in docs) {
            if (doc.conformanceLevel.name != ConformanceLevel.ADES_B_B.toString() && tsaUrl.isEmpty()) {
                error("Missing TSA URL for conformance level: ${doc.conformanceLevel.name}")
            }
        }
    }


}
