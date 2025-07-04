# 📦 Changelog

## [R5] - 2025-5-6 - Refactoring Hash & PDF Signing Flow

### 🔄 Changed
In **R5**, major architectural changes were introduced in the **PDF hash calculation**, **signature embedding**, and final signed PDF creation flows — specifically affecting the `calculateDocumentHashes` and `getSignedDocuments` methods. These operations, which were previously handled via external services, are now executed locally on the device. **All other functionality remains unchanged**.


---

### 🧮 Hash Calculation (Local)

#### 🔁 Previous (R3)

In R3, calculating PDF document hashes required sending the **base64-encoded PDF** to a remote service via `calculateDocumentHashes(...)`, along with an access token for authorization.

**Example:**
```kotlin
val documentToSign = DocumentToSign(
    Document(
        File(ClassLoader.getSystemResource("sample.pdf").path),
        "A sample pdf",
    ),
    SignatureFormat.P,
    ConformanceLevel.ADES_B_B,
    SigningAlgorithmOID.RSA,
    SignedEnvelopeProperty.ENVELOPED,
    ASICContainer.NONE,
)

val documentDigests = calculateDocumentHashes(
    listOf(documentToSign),
    credentials.first().certificate,
    HashAlgorithmOID.SHA_256,
)
```

---

#### ✅ Now (R5)

In R5, the calculation is fully **offline** and operates on **file paths** instead of base64 data. There is no need to pass an access token.

**New Example:**
```kotlin
val documentToSign =  DocumentToSign(
    "Documents/sample.pdf",             //input path
    "Documents/signed-sample.pdf",      //output path
    "A sample pdf",
    SignatureFormat.P,
    ConformanceLevel.ADES_B_B,
    SignedEnvelopeProperty.ENVELOPED,
    ASICContainer.NONE
)

val documentDigests = calculateDocumentHashes(
    listOf(documentToSign),
    credentials.first().certificate,
    HashAlgorithmOID.SHA_256,
)

```

---

### 🖋️ Signed Document Creation

#### 🔁 Previous (R3)

Signed PDF generation was handled remotely. The request object included the base64 document and required an access token.

**Example:**
```kotlin
val signatures = signHash(SigningAlgorithmOID.RSA).getOrThrow()


getSignedDocuments(
    listOf(documentToSign),
    signatures.signatures,
    credentialCertificate,
    documentDigestList.hashAlgorithmOID,
    documentDigestList.hashCalculationTime,
)
```

---

#### ✅ Now (R5)

The signed document is created **locally** by embedding the provided `signatures` into the original document. The method directly writes the result to the declared `documentOutputPath`. The method `getSignedDocuments` has been renamed to `createSignedDocuments`.

**New Example:**
```kotlin
val signatures = signHash(SigningAlgorithmOID.RSA).getOrThrow()

createSignedDocuments(signatures.signatures)
```

This embeds each `signature` into the respective input PDF (using `documentInputPath`) and creates the final signed document at `documentOutputPath`.

---



### ✅ Summary of Improvements

| Feature                            | R3 (Remote)                                       | R5 (Local)                                  |
|------------------------------------|--------------------------------------------------|---------------------------------------------|
| PDF Handling                       | Base64                                           | File Paths                                   |
| Access Token Required              | ✅ Yes                                            | ❌ No                                        |
| Hash Calculation                   | Remote API                                       | Local Processing                             |
| Signature Embedding & PDF Creation | Remote API                                       | Local Processing                             |
| Output Format                      | Base64-encoded Signed PDF                        | Written to `documentOutputPath`             |