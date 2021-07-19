#include <printer/Printer.hpp>

#include <fs.hpp>
#include <var.hpp>

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
Ecc::Api Ecc::m_api;

Ecc::Ecc() { api()->init(&m_context); }
Ecc::~Ecc() { api()->deinit(&m_context); }

SecretExchange::SecretExchange(Curve curve) {
  Key::Buffer public_buffer;

  public_buffer.fill(0);
  u32 public_key_size = public_buffer.count();
  API_RETURN_IF_ERROR();

  API_SYSTEM_CALL(
    "failed to create DH key pair",
    api()->dh_create_key_pair(
      m_context,
      static_cast<crypt_ecc_key_pair_t>(curve),
      public_buffer.data(),
      &public_key_size));

  m_public_key = Key(public_buffer, public_key_size);
}

SecretExchange::~SecretExchange() {}

SecretExchange::SharedSecret
SecretExchange::get_shared_secret(const Key &public_key) const {
  SharedSecret result;
  result.fill(0);
  API_RETURN_VALUE_IF_ERROR(result);

  API_SYSTEM_CALL(
    "failed to calculate DH shared secret",
    api()->dh_calculate_shared_secret(
      m_context,
      public_key.data().to_const_u8(),
      public_key.size(),
      result.data(),
      result.count()));

  return result;
}

DigitalSignatureAlgorithm::KeyPair
DigitalSignatureAlgorithm::create_key_pair(Curve value) {
  API_RETURN_VALUE_IF_ERROR(KeyPair());

  Key::Buffer public_key_buffer;
  Key::Buffer private_key_buffer;

  u32 public_key_size = public_key_buffer.count();
  u32 private_key_size = private_key_buffer.count();

  API_SYSTEM_CALL(
    "failed to create DSA key pair",
    api()->dsa_create_key_pair(
      m_context,
      static_cast<crypt_ecc_key_pair_t>(value),
      public_key_buffer.data(),
      &public_key_size,
      private_key_buffer.data(),
      &private_key_size));

  return KeyPair()
    .set_public_key(Key(public_key_buffer, public_key_size))
    .set_private_key(Key(private_key_buffer, private_key_size));
}

void DigitalSignatureAlgorithm::set_key_pair(const KeyPair &value) {
  API_RETURN_IF_ERROR();
  m_key_pair = value;
  API_SYSTEM_CALL(
    "failed to set DSA key pair",
    api()->dsa_set_key_pair(
      m_context,
      value.public_key().data().to_const_u8(),
      value.public_key().size(),
      value.private_key().data().to_const_u8(),
      value.private_key().size()));
}

DigitalSignatureAlgorithm::Signature
DigitalSignatureAlgorithm::sign(const var::View message_hash) {
  Signature result;
  Signature::Buffer buffer;
  u32 size = buffer.count();
  API_RETURN_VALUE_IF_ERROR(Signature(buffer, 0));

  API_SYSTEM_CALL(
    "Failed to sign hash",
    api()->dsa_sign(
      m_context,
      message_hash.to_const_u8(),
      message_hash.size(),
      buffer.data(),
      &size));

  return Signature(buffer, size);
}

bool DigitalSignatureAlgorithm::verify(
  const Signature &signature,
  const var::View message_hash) {

  return api()->dsa_verify(
           m_context,
           message_hash.to_const_u8(),
           message_hash.size(),
           signature.data().to_const_u8(),
           signature.size())
         != 0;
}

bool DigitalSignatureAlgorithm::is_signed(const fs::File &file) {
  if (file.size() < sizeof(crypt_api_signature512_marker_t)) {
    return false;
  }

  File::LocationScope ls(file);

  const size_t marker_location
    = file.size() - sizeof(crypt_api_signature512_marker_t);
  crypt_api_signature512_marker_t signature;
  file.seek(marker_location).read(View(signature).fill(0));

  return (signature.marker.start == CRYPT_SIGNATURE_MARKER_START)
         && (signature.marker.next == CRYPT_SIGNATURE_MARKER_NEXT)
         && (signature.marker.size == CRYPT_SIGNATURE_MARKER_SIZE + 512);
}

void DigitalSignatureAlgorithm::append(
  const fs::File &file,
  const Signature &signature) {

  File::LocationScope ls(file);

  crypt_api_signature512_marker_t marker = {
    .marker = {
      .start = CRYPT_SIGNATURE_MARKER_START,
      .next = CRYPT_SIGNATURE_MARKER_NEXT,
      .size = CRYPT_SIGNATURE_MARKER_SIZE + 512}};

  var::View(marker.signature).copy(signature.data());
  file.seek(0, File::Whence::end).write(var::View(marker));
}

bool DigitalSignatureAlgorithm::verify(
  const fs::File &file,
  const Key &public_key) {
  // hash the file up to the marker
  File::LocationScope ls(file);

  if (file.size() < sizeof(crypt_api_signature512_marker_t)) {
    return false;
  }
  const size_t hash_size
    = file.size() - sizeof(crypt_api_signature512_marker_t);

  auto hash = [](const fs::File &file, size_t hash_size) {
    Sha256 result;
    file.seek(0);
    fs::NullFile().write(file, result, fs::File::Write().set_size(hash_size));
    return result.output();
  }(file, hash_size);

  crypt_api_signature512_marker_t marker;
  ViewFile(View(marker)).write(file);

  const auto signature_buffer
    = [](const crypt_api_signature512_marker_t &marker) {
        Signature::Buffer buffer;
        View(buffer).copy(View(marker.signature));
        return buffer;
      }(marker);

  const Signature signature(signature_buffer, signature_buffer.count());

  return Dsa(KeyPair().set_public_key(public_key)).verify(signature, hash);
}