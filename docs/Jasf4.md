# JASF Version 4 (JsAsymSecureFile) Structure

# File Structure

## Header

Jasf Version.4는 기본적으로 ASN.1 규격을 따른다.

파일 시그너처 확인을 위해 파일에 한에서는 아래와 같은 Header가 추가된다.

**파일에 한에서만 가능하며, 통신 목적에서는 아래 해더는 제외한다.**

```
SIGNATURE(15 byte) : 0x0a 0x9b 0xd8 0x13 0x97 0x1f 0x93 0xe8 0x6b 0x7e 0xdf 0x05 0x70 0x54 0x02,
VERSION  (1 byte)  : 0x04,
{BER Encoded Payload}
```

SIGNATURE는 고정값이며

VERSION는 아래와 같다.

- 1 : (DEPRECATED) SignedSecureFile version. 1
- 2 : (DEPRECATED) SignedSecureFile version. 2
- 3 : (DEPRECATED) JsAsymSecureFile version. 3
- 4 : (RECOMMANDED) JsAsyncSecureFile version. 4



## ASN.1 Definition

```ASN.1
Jasf4 DEFINITIONS AUTOMATIC TAGS ::=
BEGIN

DefaultHeader ::= SEQUENCE {
    minorVersion [0] IMPLICIT INTEGER,
    asymAlgorithmType [1] IMPLICIT INTEGER,
    chunkCryptoAlgorithm  [2] IMPLICIT OBJECT IDENTIFIER,
		-- e.g. 2.16.840.1.101.3.4.1.42(aes256-CBC)
    dataCryptoAlgorithm  [3] IMPLICIT OBJECT IDENTIFIER,
		-- e.g. 2.16.840.1.101.3.4.1.46(aes256-GCM)
		-- e.g. 2.16.840.1.101.3.4.1.42(aes256-CBC)
    fingerprintAlgorithm [4] IMPLICIT OBJECT IDENTIFIER,
		-- e.g. 2.16.840.1.101.3.4.2.1(id-sha256)
	authKeyCryptionIv [5] IMPLICIT OCTET STRING -- always 16byte
}

PBKDF2Params ::= SEQUENCE {
               salt CHOICE {
                      specified OCTET STRING,
                      otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
               },
              iterationCount INTEGER (1..MAX),
              keyLength INTEGER (1..MAX) OPTIONAL,
              prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT algid-hmacWithSHA1
}

AuthKeyCheckData ::= SEQUENCE {
    algorithm    [0] IMPLICIT OBJECT IDENTIFIER,
    	-- e.g. 1.2.840.113549.2.9 (HMAC-SHA256) => HmacSHA256 for PBKDF2
    params       [1] EXPLICIT PBKDF2Params,
    key  [2] IMPLICIT OCTET STRING
}

AsymAlgorithmIdentifier ::= AlgorithmIdentifier

DataCryptoAlgorithmParameterSpec ::= ANY

EncryptedDataKeyInfo ::= OCTET STRING

DataKeyInfo ::= SEQUENCE {
    signature    [0] IMPLICIT OCTET STRING, -- 0x01 0xcf 0xcb 0xff
    dataKey      [1] IMPLICIT OCTET STRING,
    macKey       [2] IMPLICIT OCTET STRING OPTIONAL
}

EphemeralECPublicKey ::= ANY

Data ::= OCTET STRING

MacOfEncryptedData ::= OCTET STRING

Fingerprint ::= OCTET STRING

Timestamp ::= ANY

Chunk ::= SEQUENCE {
    id   [0] IMPLICIT INTEGER,
		-- 0x00 ~ 0x7F : Jasf Defined Header
		-- 0x80~0x7fffff : Custom header
    flags        [1] IMPLICIT INTEGER {
        encryptWithAuthKey(0)
    } (0..65535),
    data         [2] EXPLICIT ANY DEFINED BY id
}

Payload ::= SEQUENCE {
    version      [0] IMPLICIT INTEGER,
    operationType        [1] IMPLICIT ENUMERATED {
        sign(1),
        publicEncrypt(2)
    },
    chunks       [2] IMPLICIT SEQUENCE OF Chunk --% ANY_TABLE_REF (CHUNK_DATA)
}
	
--% CHUNK_DATA ANY_TABLE ::=
--% {
--%		0x01 DefaultHeader,
--%		0x10 AuthKeyCheckData,
--%		0x21 AsymAlgorithmIdentifier,
--%		0x31 DataCryptoAlgorithmParameterSpec,
--%		0x32 DataMacAlgorithm,
--%		0x33 EphemeralECPublicKey,
--%		0x34 EncryptedDataKeyInfo,
--%		0x70 Data,
--%		0x72 MacOfEncryptedData,
--%		0x76 Fingerprint,
--%		0x77 SignedFingerprint,
--%		0x79 Timestamp,
--% }

END

```



### OperationType

- 0x01 : Sign mode (Need target private key & AuthKey)

  Sign with Private Key (데이터 공개, 수정 불가)
  Crpytogram : Signature & Encrypted Data

  

- 0x02 : Public encrypt mode (Need target public key & AuthKey)

  Encrypt with Public Key (데이터 비공개, 재생성 가능)
  Crpytogram : Local Public Key & Encrypted Data





## Basic Defines

### Mode

- 0x01 : Sign mode (Need target private key & AuthKey)

  Sign with Private Key (데이터 공개, 수정 불가)
  Crpytogram : Signature & Encrypted Data

  

- 0x02 : Public encrypt mode (Need target public key & AuthKey)

  Encrypt with Public Key (데이터 비공개, 재생성 가능)
  Crpytogram : Local Public Key & Encrypted Data



## Basic Ideas

### AuthKey

**Authentication Key** 의 약자

[AuthKey](#AuthKey)는 1차적인 보호 장치이다.

1. [AuthKey](#AuthKey)가 맞았는지 틀렸는지 검증 가능해야 함.
   * Header를 읽는 과정에서 알 수 있어야 함.
   * PBKDF2를 이용함

2. 모든 데이터는 [AuthKey](#AuthKey)를 사용하여 암호화 함.
   * AuthKey를 HKDF를 이용해서 MAC Key, Encrypt Key 등을 구분함.



#### AuthKeyDerivationPool

= HKDF(algo=sha256, passphrase=[AuthKey](#AuthKey), output=64bytes)

[AuthKey](#AuthKey) 으로부터 파생된 Key Pool



#### AuthEncryptKey

 = [AuthKeyDerivationPool](#AuthKeyDerivationPool)[0:31]



#### AuthMacKey 

 = [AuthKeyDerivationPool](#AuthKeyDerivationPool)[32:63]



## Common Feature

#### Plaintext Custom Chunk

암호화되지 않은 상태의 Custom Chunk를 저장함 (in Header)



#### Encrypted Custom Chunk with AuthKey

[AuthEncryptKey](#AuthEncryptKey) 으로 암호화한 Custom Chunk를 저장함 (in Header)



## Sign Mode

**서명을 통해 데이터가 변경되지 않았음을 검증하기 위함**

### Inputs for sign

* Authentication Key
* Private Key



### Sign

#### Data to be stored

* Plain Text
* Signature
* Timestamp (File's Fingerprint)



### Verify

* Verify with Private Key



## Public Encrypt Mode

**공개키로 암호화하여 개인키로 복호화하기 위함**

### Inputs for Encrypt

* Authentication Key
* Public Key



Encrypt-then-MAC 사용이유 : 공개키를 모르고, Payload만 있을 때 데이터 변경 방지를 위해 (CTR방식의 암호화 경우 키를 모르더라도 Bit 반전이 가능함)



### Encrypt (RSA Key)

DataKey = Random Key

MacKey = Random Key

#### Data to be stored

* Encrypted Data Key (Encrypt with RSA)
* Encrypted Data (Encrypt with DataKey)
* Encrypt-then-MAC
* Timestamp (File's Fingerprint)



### Encrypt (EC Key)

DataKeyDerivationPool = HKDF(algo=sha256, passphrase=ECDH(PublicKey, EphemeralPrivateKey), output=96bytes)

dataEncryptKey = DataKeyDerivationPool[0:32]

dataMacKey = DataKeyDerivationPool[32:64]

dhCheckData = DataKeyDerivationPool[64:96]

#### Data to be stored

* Ephemeral EC Public Key (for ECDH)
* Encrypted Data (Encrypt with DataKey)
* Encrypt-then-MAC
* Timestamp (File's Fingerprint)



## Read Policy

### chunk 순서

Chunk는 먼저것이 우선 읽음.

중복된 Chunk는 나중것을 무시함.



### Chunk 읽기

Fingerprint 이후 Chunk는 Timestamp외에는 제외함

(Fingerprint이후 chunk삽입 공격 방지)



## Chunks

| chunkId | Name                     | sign     | PubEnc            | encryptWithAuthKey |
| ------- | ------------------------ | -------- | ----------------- | ------------------ |
| 0x01    | DefaultHeader            | O        | O                 | NO                 |
| 0x10    | AuthKeyCheckData         | O        | O                 | NO                 |
| 0x21    | AsymAlgorithmParam       | O        | O                 | NO                 |
| 0x31    | DataCryptoAlgorithmParam | O        | O                 | NO                 |
| 0x32    | DataMacAlgorithm         | X        | O                 | NO                 |
| 0x33    | EphemeralECPublicKey     | X        | O                 | YES                |
| 0x34    | DataKeyInfo              | O        | X                 | YES                |
| 0x35    | EncryptedDataKeyInfo     | X        | O (RSA Mode Only) | NO                 |
| 0x39    | DHCheckData              | X        | O (EC Mode Only)  | YES                |
| 0x70    | Data                     | O        | O                 | NO                 |
| 0x72    | MacOfEncryptedData       | X        | O                 | NO                 |
| 0x76    | Fingerprint              | O        | O                 | NO                 |
| 0x78    | SignedFingerprint        | O        | X                 | NO                 |
| 0x79    | Timestamp                | Optional | Optional          | NO                 |



### Data

stream성 데이터 혹은 undefined-size data를 저장하기 위해 Data Chunk는 중복 사용 가능하다. dataKey로 암호화하는 경우 데이터는 연속된 형태로 암호화된 상태로 저장되며 마지막 DataChunk는 Final block이 들어가게 된다.



### MacOfEncryptedData





### Fingerprint

= HASH(algo = *fingerprintAlgorithm*, data = **asn1-begin** ~ **before Fingerprint**)



### Timestamp

(rfc3161 timestamp)

= SignedTimestamp(data = *Fingerprint*)











## Reader mechanism

1. DefaultHeaderChunk & AuthKeyCheckDataChunk 를 읽는다.
2. authKey가 설정되었으면 (reader.init(...)) authKey가 옳은지 검증한다.
   * 틀리면 error객체에 오류 내용을 저장하고, error event 를 발생한다.
3. authKey가 설정되지 않았으면 (init가 호출되지 않았으면) 검증을 미룬다.
   * 이후 init를 호출하면 authKey가 옳은지 검증한다.
   * 만일 이 때 authKey검증세 실패시 err객체에 오류 내용을 저장하고 event event를 호출하지 않으며, init메서드의 promise를 Reject 처리 한다.
4. authKey가 확인되지 않은 체 다른 Header chunk를 읽으면 암호화된 chunk는 복호화를 보류한다.



