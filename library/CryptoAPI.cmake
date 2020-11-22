
if(NOT DEFINED IS_SDK)
	include(InetAPI)
	sos_sdk_include_target(CryptoAPI "${API_CONFIG_LIST}")
endif()
