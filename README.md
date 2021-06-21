# CryptoAPI

CryptoAPI is a cryptography access API following the Stratify Labs [API framework](https://github.com/StratifyLabs/API). On desktop applications, it uses mbedtls under the hood for cryptography functions. On embedded, it will use whatever crypto library is provided by Stratify OS.

## Building

The CryptoAPI is designed to be built as part of an SDK super project. Instructions for building are at the [SDK API project](https://github.com/StratifyLabs/SdkAPI).

## Usage

### Random Number Generator

```c++
#include <crypto.hpp>

//randomize a buffer
char buffer[16];
Random().seed().randomize(View(buffer));

//create a random string of 16 bytes (32 characters)
const auto random_string = Random().to_string<var::GeneralString>(16);
```


### AES

```c++
#include <crypto.hpp>

const auto key = Key(); //random key and IV

//randomize data to encrypt -- SIZE must be a multiple of 16
var::Array<u8, 16> plain_buffer;
Random().seed().randomize(plain_buffer);

var::Array<u8, 16> cipher_buffer;

//encrypt
Aes()
  .set_key(key)
  .encrypt_cbc(Aes::EncryptCbc()
    .set_plain(buffer)
    .set_cipher(cipher));

//decrypt
Aes()
  .set_key(key)
  .decrypt_cbc(Aes::EncryptCbc()
    .set_plain(buffer)
    .set_cipher(cipher));

```

### SHA256 Hash

```c++
#include <crypto.hpp>

const auto str = "Hello World\n";
printf("hash is %s\n", 
  Sha256().update(var::View(str)).output().to_string().cstring());

```