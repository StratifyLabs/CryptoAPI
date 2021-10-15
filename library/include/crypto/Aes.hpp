// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#ifndef CRYPTOAPI_CRYPTO_AES_HPP_
#define CRYPTOAPI_CRYPTO_AES_HPP_

#include <sdk/api.h>

#include <api/api.hpp>
#include <fs/File.hpp>
#include <var/Data.hpp>
#include <var/StackString.hpp>

#if defined __link && !defined CRYPT_AES_API_REQUEST
#include <mbedtls_api.h>
#define CRYPT_AES_API_REQUEST &mbedtls_crypt_aes_api
#endif

#include "Random.hpp"

namespace crypto {

class Aes : public api::ExecutionContext {
public:
  using InitializationVector = var::Array<u8, 16>;
  using Key256 = var::Array<u8, 32>;
  using Key128 = var::Array<u8, 16>;
  using Iv = InitializationVector;

  class Key {
  public:
    class Construct {
      API_AC(Construct, var::StringView, key);
      API_AC(Construct, var::StringView, initialization_vector);
    };

    explicit Key(const Construct &options) {
      var::View(m_key).copy(var::Data::from_string(options.key()));
      var::View(m_initialization_vector)
          .copy(var::Data::from_string(options.initialization_vector()));
    }

    Key(const Key256 & key256) : m_key(key256){}
    Key(const Key256 & key256, const Iv & iv) : m_key(key256), m_initialization_vector(iv){}

    Key() {
      // 256-bit key length
      Random().seed().randomize(var::View(m_key));
      Random().seed().randomize(var::View(m_initialization_vector));
    }

    Key& nullify(){
      m_key.fill(0);
      m_initialization_vector.fill(0);
      return *this;
    }

    bool is_null() const {
      return is_key_null() && is_iv_null();
    }

    bool is_key_null() const {
      for(auto value: m_key){
        if( value != 0 ){
          return false;
        }
      }
      return true;
    }

    bool is_iv_null() const {
      for(auto value: m_initialization_vector){
        if( value != 0 ){
          return false;
        }
      }
      return true;
    }

    static constexpr const char * get_null_key256_string(){
      return "0000000000000000000000000000000000000000000000000000000000000000";
    }

    static constexpr const char * get_null_key128_string(){
      return "00000000000000000000000000000000";
    }

    const Key256 &key256() const { return m_key; }
    Key256 get_key256() const { return m_key; }
    Key128 get_key128() const {
      Key128 result;
      var::View(result).copy(m_key);
      return result;
    }

    Key &set_key(const Key128 &key) {
      var::View(m_key).fill(0).copy(var::View(key));
      return *this;
    }

    Key &set_key(const Key256 &key) {
      m_key = key;
      return *this;
    }

    const InitializationVector &initialization_vector() const {
      return m_initialization_vector;
    }

    var::GeneralString get_key256_string() const {
      return var::View(m_key).to_string<var::GeneralString>();
    }

    var::KeyString get_key128_string() const {
      return var::View(m_key).to_string<var::KeyString>();
    }

    var::KeyString get_initialization_vector_string() const {
      return var::View(m_initialization_vector).to_string<var::KeyString>();
    }

  private:
    Key256 m_key;
    InitializationVector m_initialization_vector;
  };

  Aes();
  ~Aes();

  Aes(const Aes &a) = delete;
  Aes &operator=(const Aes &aes) = delete;

  Aes(Aes &&a){
    std::swap(m_context, a.m_context);
  }

  Aes &operator=(Aes &&a){
    std::swap(m_context, a.m_context);
    return *this;
  }

  Aes &set_key128(const var::View &key);
  Aes &set_key256(const var::View &key);

  Aes &set_initialization_vector(const var::View &value);

  const InitializationVector &initialization_vector() const {
    return m_initialization_vector;
  }

  static size_t get_padding(size_t input_size) {
    const size_t tmp = input_size % 16;
    return tmp ? (16 - tmp) : 0;
  }

  static var::Data get_padded_data(const var::View input, u8 padding_value = 0xff) {
    const auto padding_size = get_padding(input.size());
    auto result = var::Data(input.size() + padding_size);
    var::View(result).fill<u8>(padding_value).copy(input);
    return result;
  }

  class Crypt {
    API_AC(Crypt, var::View, plain);
    API_AC(Crypt, var::View, cipher);
  };

  using EncryptEcb = Crypt;
  using DecryptEcb = Crypt;

  const Aes &encrypt_ecb(const EncryptEcb &options) const;
  const Aes &decrypt_ecb(const DecryptEcb &options) const;

  var::Data encrypt_ecb(var::View input) const {
    var::Data result(input.size());
    encrypt_ecb(Crypt().set_plain(input).set_cipher(var::View(result)));
    return result;
  }

  var::Data decrypt_ecb(var::View input) const {
    var::Data result(input.size());
    decrypt_ecb(Crypt().set_cipher(input).set_plain(var::View(result)));
    return result;
  }

  using EncryptCbc = Crypt;
  using DecryptCbc = Crypt;

  const Aes &encrypt_cbc(const EncryptCbc &options) const;
  const Aes &decrypt_cbc(const DecryptCbc &options) const;

  var::Data encrypt_cbc(var::View input) const {
    var::Data result(input.size());
    encrypt_cbc(Crypt().set_plain(input).set_cipher(var::View(result)));
    return result;
  }

  var::Data decrypt_cbc(var::View input) const {
    var::Data result(input.size());
    decrypt_cbc(Crypt().set_cipher(input).set_plain(var::View(result)));
    return result;
  }

#if 0 // not yet implemented
  Aes &encrypt_ctr(const Crypt &options);
  Aes &decrypt_ctr(const Crypt &options);
#endif

private:
  using Api = api::Api<crypt_aes_api_t, CRYPT_AES_API_REQUEST>;
  static Api m_api;

  void *m_context = nullptr;
  mutable InitializationVector m_initialization_vector;

  static Api &api() { return m_api; }
};

template <class Derived> class AesAccess : public Aes {
public:
  Derived &set_key128(const var::View &key) {
    return static_cast<Derived &>(Aes::set_key128(key));
  }

  Derived &set_key256(const var::View &key) {
    return static_cast<Derived &>(Aes::set_key256(key));
  }

  Derived &set_initialization_vector(const var::View &value) {
    return static_cast<Derived &>(Aes::set_initialization_vector(value));
  }
};

class AesCbcEncrypter : public var::Transformer,
                        public AesAccess<AesCbcEncrypter> {
public:
  int transform(
      const var::Transformer::Transform &options) const override final;

  size_t page_size_boundary() const override { return 16; }
};

class AesCbcDecrypter : public var::Transformer,
                        public AesAccess<AesCbcDecrypter> {
public:
  int transform(
      const var::Transformer::Transform &options) const override final;

  size_t page_size_boundary() const override { return 16; }
};

} // namespace crypto

namespace printer {
class Printer;
Printer &operator<<(Printer &printer, const crypto::Aes::Key &a);
} // namespace printer

#endif // CRYPTOAPI_CRYPTO_AES_HPP_
