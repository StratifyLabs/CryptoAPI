// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include "crypto/Sha256.hpp"

using namespace crypto;

namespace {
static auto &sha_api() {
  static api::Api<crypt_hash_api_t, CRYPT_SHA256_API_REQUEST> instance;
  return instance;
}
} // namespace

Sha256::Sha256() {
  if (!sha_api().is_valid()) {
    exit_fatal("Sha256 api missing");
  }
  API_RETURN_IF_ERROR();
  void * context = nullptr;
  API_SYSTEM_CALL("", sha_api()->init(&context));
  API_RETURN_IF_ERROR();
  m_state = {State{context}, &deleter};
  API_SYSTEM_CALL("", sha_api()->start(context));
  m_is_finished = false;
}

void Sha256::deleter(Sha256::State *state) {
  if( state->context ){
    sha_api()->deinit(&state->context);
  }
}

const Sha256 &Sha256::update(const var::View &input) const {
  if (m_is_finished) {
    API_RETURN_VALUE_ASSIGN_ERROR(*this, "", EINVAL);
  }
  API_RETURN_VALUE_IF_ERROR(*this);
  API_SYSTEM_CALL(
    "Sha256::update",
    sha_api()->update(m_state->context, input.to_const_u8(), input.size()));
  return *this;
}

void Sha256::finish() const {
  if (!m_is_finished) {
    API_RETURN_VALUE_IF_ERROR();
    m_is_finished = true;
    API_SYSTEM_CALL(
      "Sha256::finish",
      sha_api()->finish(
        m_state->context,
        (unsigned char *)m_output.data(),
        m_output.count()));
  }
}

Sha256::Hash
Sha256::append_aligned_hash(const fs::FileObject &file_object, u8 fill) {
  fs::File::LocationGuard location_guard(file_object);
  const size_t padding_length = [](size_t image_size) -> size_t {
    size_t padding_length = sizeof(Hash) - image_size % sizeof(Hash);
    if (padding_length == sizeof(Hash)) {
      padding_length = 0;
    }
    return padding_length;
  }(file_object.size());

  var::Array<u8, sizeof(Hash)> padding{};
  padding.fill(fill);

  file_object.seek(0, fs::File::Whence::end)
    .write(var::View(padding.data(), padding_length));

  Sha256 hash_calculated;
  fs::NullFile().write(
    file_object.seek(0),
    fs::File::Write().set_transformer(&hash_calculated));

  const Hash hash_calculated_output = hash_calculated.output();
  file_object.write(hash_calculated_output);

  return hash_calculated_output;
}

bool Sha256::check_aligned_hash(const fs::FileObject &file_object) {
  fs::File::LocationGuard location_guard(file_object);
  Sha256 hash_calculated;
  fs::NullFile().write(
    file_object.seek(0),
    fs::File::Write()
      .set_transformer(&hash_calculated)
      .set_size(file_object.size() - sizeof(Hash)));
  Hash hash_read;
  file_object.read(hash_read);
  return hash_read == hash_calculated.output();
}
Sha256::Hash Sha256::from_string(const var::StringView value) {
  API_ASSERT(value.length() == 64);
  Hash result;
  var::View(result).from_string(value);
  return result;
}
Sha256::Hash Sha256::get_hash(const fs::FileObject &file) {
  Sha256 hash;
  fs::NullFile().write(file, hash);
  return hash.output();
}
