# CryptoAPI

`CryptoAPI` is a cryptography access API following the Stratify Labs [API framework](https://github.com/StratifyLabs/API). On desktop applications, it uses `mbedtls` under the hood for cryptography functions. On embedded, it will use whatever crypto library is provided by Stratify OS.


## How to Build

The `CryptoAPI` library is designed to be a CMake sub-project. To build, please use one of these projects:

- Desktop [Command Line Interface](https://github.com/StratifyLabs/cli)
- [Stratify OS on Nucleo-144](https://github.com/StratifyLabs/StratifyOS-Nucleo144)

## Usage

### Random Number Generator

```cpp
#include <crypto.hpp>

//randomize a buffer
char buffer[16];
Random().seed().randomize(View(buffer));

//create a random string of 16 bytes (32 characters)
const auto random_string = Random().to_string<var::GeneralString>(16);
```


### AES

```cpp
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

```cpp
#include <crypto.hpp>

const auto str = "Hello World\n";
printf("hash is %s\n", 
  Sha256().update(var::View(str)).output().to_string().cstring());

```