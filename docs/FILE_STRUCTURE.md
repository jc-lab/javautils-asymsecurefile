# JASF (JsAsymSecureFile) Structure

파일의 시작 구조는 아래와 같다.

```
SIGNATURE(15 byte) : 0x0a 0x9b 0xd8 0x13 0x97 0x1f 0x93 0xe8 0x6b 0x7e 0xdf 0x05 0x70 0x54 0x02,
VERSION  (1 byte)  : 0x03,
{VERSION별 데이터}
```

SIGNATURE는 고정값이며

VERSION는 아래와 같다.

- 1 : (DEPRECATED) SignedSecureFile version.1
- 2 : (NOT RECOMMANDED) SignedSecureFile version.2
- 3 : (RECOMMANDED) JsAsymSecureFile

JsAsymSecureFile은 SignedSecureFile에 대한 하위 호환성 읽기를 지원한다. (JsAsymSecureFileWriter로 작성된 파일은 SignedSecureFile에서 읽기 불가)



## Basic Defines

**AuthEncKey** = HmacSHA256(key = authKey, message=defaultHeaderChunk.seed)

**DataKey**

* PUBLIC_ENCRYPT Mode :
  SeedKey = {EC: ECDH Shared Key, RSA : Random}

  HmacSHA512(key = authKey, message = seedKey) -> \[32bytes:dataKey, 32bytes:macKey\]

* SIGN Mode : dataKey=AuthEncKey, macKey=AuthKey



## JASF Structure

VERSION >= 3 인 JsAsymSecureFile에 대한 구조는 아래와 같이 이어진다.

```
DefaultHeader: {
	operationType: (1byte),
	
},
Chunks [{
	/* Chunk */
	Chunk Type : (1byte or 3byte),
	Chunk Length : (2byte, unsigned short),
	Chunk Data
}, ...],
Data Chunk : {
	Chunk Type : Encrypted Data (1byte),
	Chunk Length : Chunk Size, /* 데이터 사이즈가 정해진경우 고정사이즈, 아닌경우 4K단위로 chunk화함 */
	Encrypted Data
}...,
File Fingerprint Chunk [LAST - 0] {
	Chunk Type : File Fingerprint,
	Chunk Length : (2byte, unsigned short),
	Data : MiniChunks
	[MiniChunk {
	    Chunk Type : (1byte),
	    Chunk Size : (2byte),
	    Data
	}]
	Chunk Type
	- 0x01 : Fingerprint
	- 0x02 : Signature (Sign Mode)
	- 0x03 : Mac (PUBLIC_ENCRYPT Mode)
	,
    Footer Chunk Size (2byte),
    Total File Size (8bytes)
}
```

### Mode

- 0x01 : Sign mode (Need target private key & AuthKey)

  Sign with Private Key (데이터 공개, 수정 불가)
  Crpytogram : Signature & Encrypted Data

  

- 0x02 : Public encrypt mode (Need target public key & AuthKey)

  Encrypt with Public Key (데이터 비공개, 재생성 가능)
  Crpytogram : Local Public Key & Encrypted Data

### Chunk Type

Chunk Type는 1byte or 3byte로써 길이 및 값은 아래와 같이 정해진다.

- **0x00 ~ 0x7F** : JASF Defined Chunk Type

- **0x8[F], [0xXX 0xXX]** : User Defined Chunk Type (Little Endian)

  - **F** : Flags
    0x01 : Encrypted Data with Custom Key [Chunk Data : *Algorithm* oid(4byte), Encrypted Data]
    0x02 : Signed Signature

    - Sign mode : Sign with target private key
    - Public encrypt mode : Sign with local private key

    0x03 : Encrypted Data with AuthEncKey

  - **0xXX 0xXX** : User Defiend Type



