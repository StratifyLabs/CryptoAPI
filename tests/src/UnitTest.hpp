﻿// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include <cstdio>

#include "api/api.hpp"
#include "chrono.hpp"
#include "crypto.hpp"
#include "fs.hpp"
#include "printer.hpp"
#include "sys.hpp"
#include "test/Test.hpp"
#include "var.hpp"

using A = crypto::Aes;
using S = crypto::Sha256;
using R = crypto::Random;

class UnitTest : public test::Test {
public:
  UnitTest(var::StringView name) : test::Test(name) {}

  bool execute_class_api_case() {

    if (!aes_api_case()) {
      return false;
    }

    if (!random_api_case()) {
      return false;
    }

    if (!sha256_api_case()) {
      return false;
    }

    return true;
  }

  bool random_api_case() {

    char buffer[16];

    Random().seed().randomize(View(buffer));

    printer().key("buffer", View(buffer).to_string<GeneralString>());

    printer().key(
        "random",
        View(DataFile().reserve(12).write(NullFile(12), Random().seed()).data())
            .to_string<GeneralString>());

    return true;
  }

  bool sha256_api_case() {

    const StringView input =
        "With the newest hardware (CPU and GPU) improvements it is become "
        "possible to decrypt SHA256 algorithm back. So it is no longer "
        "recommended to use it for password protection or other similar use "
        "cases. Some years ago you would protect your passwords from hackers "
        "by storing SHA256 encrypted password in the your data base. This is "
        "no longer a case.";

    const Data output = Data::from_string(
        "81bb7b29be293aeab191404e671a8a8c7687756b632cbd6a29ee65f909b30bcf");

    {
      Sha256 sha256;
      TEST_ASSERT(NullFile().write(ViewFile(View(input)), sha256).is_success());
      TEST_ASSERT(View(sha256.output()) == View(output));
      TEST_ASSERT(View(Sha256().update(View(input)).output()) == View(output));
    }

    return true;
  }

  bool aes_api_case() {

    Printer::Object po(printer(), "aes_api_case()");
    const Data key128 = Data::from_string("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");
    const Data key256 = Data::from_string(
        "08090A0B0D0E0F10121314151718191A1C1D1E1F21222324262728292B2C2D2E");
    const Data plain128 = Data::from_string("014BAF2278A69D331D5180103643E99A");
    const Data plain256 = Data::from_string("069A007FC76A459F98BAF917FEDF9521");
    {
      Printer::Object po(printer(), "ecb");

      const Data cipher128 =
          Data::from_string("6743C3D1519AB4F2CD9A78AB09A511BD");

      PRINTER_TRACE(printer(), "");

      const Data cipher256 =
          Data::from_string("080e9517eb1677719acf728086040ae3");

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(Aes().set_key128(key128).encrypt_ecb(View(plain128)) ==
                  cipher128);

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(Aes().set_key256(key256).encrypt_ecb(View(plain256)) ==
                  cipher256);

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(Aes().set_key128(key128).decrypt_ecb(View(cipher128)) ==
                  plain128);

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(Aes().set_key256(key256).decrypt_ecb(View(cipher256)) ==
                  plain256);
    }

    {
      Printer::Object po(printer(), "cbc");
      const Data iv = Data::from_string("E8E9EAEBEDEEEFF0F2F3F4F5F7F8F9FA");

      const Data cipher128 =
          Data::from_string("d538ce674bcbf555aba94b74bba25e45");

      PRINTER_TRACE(printer(), "");

      const Data cipher256 =
          Data::from_string("c56b404deb3764bd3805eb3f10204e5c");

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(
          Aes().set_initialization_vector(iv).set_key128(key128).encrypt_cbc(
              View(plain128)) == cipher128);

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(
          Aes().set_initialization_vector(iv).set_key256(key256).encrypt_cbc(
              View(plain256)) == cipher256);

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(
          Aes().set_initialization_vector(iv).set_key128(key128).decrypt_cbc(
              View(cipher128)) == plain128);

      PRINTER_TRACE(printer(), "");
      TEST_ASSERT(
          Aes().set_initialization_vector(iv).set_key256(key256).decrypt_cbc(
              View(cipher256)) == plain256);

      {
        Printer::Object po(printer(), "cbc-file");

        TEST_ASSERT(View(DataFile()
                             .reserve(16)
                             .write(ViewFile(View(plain128)),
                                    AesCbcEncrypter()
                                        .set_initialization_vector(iv)
                                        .set_key128(key128))
                             .data()) == View(cipher128));

        TEST_ASSERT(View(DataFile()
                             .reserve(32)
                             .write(ViewFile(View(plain256)),
                                    AesCbcEncrypter()
                                        .set_initialization_vector(iv)
                                        .set_key256(key256))
                             .data()) == View(cipher256));
      }
    }

    return true;
  }

private:
};
