
if(NOT DEFINED IS_SDK AND CMSDK_IS_ARM)
	cmsdk_include_target(tinycrypt_kernel "${API_CONFIG_LIST}")
endif()
