#include <printer/Printer.hpp>

#include "crypto/Ecc.hpp"

namespace printer {
class Printer;
Printer &
operator<<(Printer &printer, const crypto::DigitalSignature::KeyPair &a) {
  return printer.key("public ", a.public_key().to_string())
    .key("private", a.private_key().to_string());
}

Printer &
operator<<(Printer &printer, const crypto::SecretExchange::SharedSecret &a) {
  return printer.key("content", var::View(a).to_string<var::GeneralString>());
}
} // namespace printer

using namespace crypto;
Ecc::Api Ecc::m_api;

Ecc::Ecc() { api()->init(&m_context); }
Ecc::~Ecc() { api()->deinit(&m_context); }

SecretExchange::SecretExchange(Curve curve) {
  Key::Buffer public_buffer;

  public_buffer.fill(0);
  u32 public_key_size = public_buffer.count();

  api()->dh_create_key_pair(
    m_context,
    static_cast<crypt_ecc_key_pair_t>(curve),
    public_buffer.data(),
    &public_key_size);

  m_public_key = Key(public_buffer, public_key_size);
}

SecretExchange::~SecretExchange() {}

SecretExchange::SharedSecret
SecretExchange::get_shared_secret(const Key &public_key) const {
  SharedSecret result;
  result.fill(0);

  api()->dh_calculate_shared_secret(
    m_context,
    public_key.data().to_const_u8(),
    public_key.size(),
    result.data(),
    result.count());

  return result;
}

DigitalSignature::KeyPair DigitalSignature::create_key_pair(Curve value) {

  Key::Buffer public_key_buffer;
  Key::Buffer private_key_buffer;

  u32 public_key_size = public_key_buffer.count();
  u32 private_key_size = private_key_buffer.count();

  api()->dsa_create_key_pair(
    m_context,
    static_cast<crypt_ecc_key_pair_t>(value),
    public_key_buffer.data(),
    &public_key_size,
    private_key_buffer.data(),
    &private_key_size);

  return KeyPair()
    .set_public_key(Key(public_key_buffer, public_key_size))
    .set_private_key(Key(private_key_buffer, private_key_size));
}

DigitalSignature &DigitalSignature::set_key_pair(const KeyPair &value) {

  api()->dsa_set_key_pair(
    m_context,
    value.public_key().data().to_const_u8(),
    value.public_key().size(),
    value.private_key().data().to_const_u8(),
    value.private_key().size());

  return *this;
}

DigitalSignature::Signature
DigitalSignature::sign(const var::StringView message_hash) {

  Signature result;
  Signature::Buffer buffer;
  u32 size = buffer.count();
  api()->dsa_sign(
    m_context,
    (u8 *)message_hash.data(),
    message_hash.length(),
    buffer.data(),
    &size);

  return Signature(buffer, size);
}

bool DigitalSignature::verify(
  const Signature &signature,
  const var::StringView message_hash) {

  return api()->dsa_verify(
           m_context,
           (const u8 *)message_hash.data(),
           message_hash.length(),
           signature.data().to_const_u8(),
           signature.size())
         != 0;
}
