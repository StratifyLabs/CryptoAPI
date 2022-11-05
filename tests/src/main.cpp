// Copyright 2020-2021 Tyler Gilbert and Stratify Labs, Inc; see LICENSE.md

#include <signal.h>

#include "UnitTest.hpp"

#define VERSION "0.1"
#include <sys/Cli.hpp>

using namespace test;

int main(int argc, char *argv[]) {
  sys::Cli cli(argc, argv);

  api::catch_segmentation_fault();

  {
    auto scope = Test::Scope<printer::Printer>(test::Test::Initialize()
                                                 .set_name(cli.get_name())
                                                 .set_version(VERSION)
                                                 .set_git_hash(CMSDK_GIT_HASH));

    Test::printer().set_verbose_level(cli.get_option("verbose"));
    UnitTest(cli.get_name()).execute(cli);
  }

  exit(test::Test::final_result() == false);

  return 0;
}
