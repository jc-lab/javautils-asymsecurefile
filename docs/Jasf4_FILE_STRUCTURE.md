# JASF Version 4 (JsAsymSecureFile) Structure

파일의 시작 구조는 아래와 같다.

```
SIGNATURE(15 byte) : 0x0a 0x9b 0xd8 0x13 0x97 0x1f 0x93 0xe8 0x6b 0x7e 0xdf 0x05 0x70 0x54 0x02,
VERSION  (1 byte)  : 0x04,
{BER Encoded Payload}
```

SIGNATURE는 고정값이며

VERSION는 아래와 같다.

- 1 : (DEPRECATED) SignedSecureFile version. 1
- 2 : (NOT RECOMMANDED) SignedSecureFile version. 2
- 3 : (NOT RECOMMANDED) JsAsymSecureFile version. 3
- 4 : (RECOMMANDED) JsAsyncSecureFile version. 4



## Basic Defines

**AuthEncKey** = HmacSHA256(key = authKey, message=defaultHeaderChunk.seed)

**DataKey**

* PUBLIC_ENCRYPT Mode :
  SeedKey = {EC: ECDH Shared Key, RSA : Random}

  HmacSHA512(key = authKey, message = seedKey) -> \[32bytes:dataKey, 32bytes:macKey\]

* SIGN Mode : dataKey=AuthEncKey, macKey=AuthKey



## JASF4 Structure

VERSION == 4 인 JsAsymSecureFile에 대한 구조는 아래와 같이 이어진다.

```

    /*
    Version Header
	Jasf4Payload ::= SEQUENCE {
		defaultHeader DefaultHeader,
		NULL, (Start Data),
		chunks SEQUENCE OF Chunk
	}
	Footer
    */
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



