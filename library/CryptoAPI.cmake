
if (NOT DEFINED API_IS_SDK)
  include(InetAPI)
  cmsdk_include_target(CryptoAPI "${API_CONFIG_LIST}")
endif ()
