#include <printer/Printer.hpp>

#include "crypto/Ecc.hpp"
#include "crypto/Sha256.hpp"

namespace printer {
class Printer;
Printer &operator<<(
  Printer &printer,
  const crypto::DigitalSignatureAlgorithm::KeyPair &a) {
  return printer.key("public ", a.public_key().to_string())
    .key("private", a.private_key().to_string());
}

Printer &
operator<<(Printer &printer, const crypto::SecretExchange::SharedSecret &a) {
  return printer.key("content", var::View(a).to_string<var::GeneralString>());
}

} // namespace printer

using namespace crypto;
using namespace fs;
using namespace var;

namespace {
auto &ecc_api() {
  static api::Api<crypt_ecc_api_t, CRYPT_ECC_API_REQUEST> instance;
  return instance;
}
} // namespace

Ecc::Ecc()
  : m_state{
    []() {
      void *context = nullptr;
      ecc_api()->init(&context);
      return State{context};
    }(),
    &deleter} {}

void Ecc::deleter(State *state) {
  if( state->context ) {
    ecc_api()->deinit(&state->context);
  }
}

SecretExchange::SecretExchange(Curve curve) {
  auto public_buffer = PublicKey::Buffer().fill(0);
  auto public_key_size = u32(public_buffer.count());
  API_RETURN_IF_ERROR();

  API_SYSTEM_CALL(
    "failed to create DH key pair",
    ecc_api()->dh_create_key_pair(
      m_state->context,
      static_cast<crypt_ecc_key_pair_t>(curve),
      public_buffer.data(),
      &public_key_size));

  m_public_key = PublicKey(public_buffer);
}

SecretExchange::SharedSecret
SecretExchange::get_shared_secret(const PublicKey &public_key) const {
  SharedSecret result;
  result.fill(0);
  API_RETURN_VALUE_IF_ERROR(result);

  API_SYSTEM_CALL(
    "failed to calculate DH shared secret",
    ecc_api()->dh_calculate_shared_secret(
      m_state->context,
      public_key.data().to_const_u8(),
      public_key.size(),
      result.data(),
      result.count()));

  return result;
}

DigitalSignatureAlgorithm::KeyPair
DigitalSignatureAlgorithm::create_key_pair(Curve value) {
  API_RETURN_VALUE_IF_ERROR(KeyPair());

  PublicKey::Buffer public_key_buffer;
  PrivateKey::Buffer private_key_buffer;

  u32 public_key_size = public_key_buffer.count();
  u32 private_key_size = private_key_buffer.count();

  API_SYSTEM_CALL(
    "failed to create DSA key pair",
    ecc_api()->dsa_create_key_pair(
      m_state->context,
      static_cast<crypt_ecc_key_pair_t>(value),
      public_key_buffer.data(),
      &public_key_size,
      private_key_buffer.data(),
      &private_key_size));

  API_ASSERT(public_key_size == public_key_buffer.count());
  API_ASSERT(private_key_size == private_key_buffer.count());

  return KeyPair()
    .set_public_key(PublicKey(public_key_buffer))
    .set_private_key(PrivateKey(private_key_buffer));
}

void DigitalSignatureAlgorithm::set_key_pair(const KeyPair &value) {
  API_RETURN_IF_ERROR();
  m_key_pair = value;
  API_SYSTEM_CALL(
    "failed to set DSA key pair",
    ecc_api()->dsa_set_key_pair(
      m_state->context,
      value.public_key().data().to_const_u8(),
      value.public_key().size(),
      value.private_key().data().to_const_u8(),
      value.private_key().size()));
}

DigitalSignatureAlgorithm::Signature
DigitalSignatureAlgorithm::sign(const var::View message_hash) const {
  Signature result;
  Signature::Buffer buffer;
  u32 size = buffer.count();
  API_RETURN_VALUE_IF_ERROR(Signature());

  API_SYSTEM_CALL(
    "Failed to sign hash",
    ecc_api()->dsa_sign(
      m_state->context,
      message_hash.to_const_u8(),
      message_hash.size(),
      buffer.data(),
      &size));

  API_ASSERT(size == buffer.count());

  return Signature(buffer);
}

bool DigitalSignatureAlgorithm::verify(
  const Signature &signature,
  const var::View message_hash) {

  return ecc_api()->dsa_verify(
           m_state->context,
           message_hash.to_const_u8(),
           message_hash.size(),
           signature.data().to_const_u8(),
           signature.size())
         == 1;
}
