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

DataKeyDerivationPool = HKDF(algo=sha256, passphrase=ECDH(PublicKey, EphemeralPrivateKey), output=64bytes)

DataEncryptKey = DataKeyDerivationPool[0:31]

#### Data to be stored

* Ephemeral EC Public Key (for ECDH)
* Encrypted Data (Encrypt with DataKey)
* Encrypt-then-MAC
* Timestamp (File's Fingerprint)

