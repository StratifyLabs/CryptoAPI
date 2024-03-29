// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include "crypto/Random.hpp"
#include "chrono/ClockTime.hpp"
#include "chrono/MicroTime.hpp"

using namespace crypto;

Random::Api Random::m_api;

Random::Random() {
  API_RETURN_IF_ERROR();
  if (!api().is_valid()) {
    API_RETURN_ASSIGN_ERROR("missing api", ENOTSUP);
  } else {
    API_RETURN_IF_ERROR();
    void * result = nullptr;
    m_context = {get_context(), &deleter};
    API_RETURN_IF_ERROR();
    seed(var::View());
  }
}

void *Random::get_context() {
  API_RETURN_VALUE_IF_ERROR(nullptr);
  void * result = nullptr;
  API_SYSTEM_CALL("random", api()->init(&result));
  return result;
}


void Random::deleter(void * context) {
  if (context != nullptr) {
    api()->deinit(&context);
  }
}


Random &Random::seed() {
  var::Array<u32, 64> list{};
  for (u32 &item : list) {
    item = ~chrono::ClockTime::get_system_time().nanoseconds();
    chrono::wait(chrono::MicroTime(item % 1000));
  }
  return seed(list);
}

Random &Random::seed(const var::View source_data) {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(m_context != nullptr);
  API_SYSTEM_CALL(
    "",
    api()->seed(m_context.get(), source_data.to_const_u8(), source_data.size()));
  return *this;
}

const Random &Random::randomize(var::View destination_data) const {
  API_RETURN_VALUE_IF_ERROR(*this);
  API_ASSERT(m_context != nullptr);
  API_SYSTEM_CALL(
    "",
    api()
      ->random(m_context.get(), destination_data.to_u8(), destination_data.size()));
  return *this;
}

var::Data Random::to_data(u32 size) const {
  var::Data result(size);
  randomize(result);
  return result;
}
