cmake_minimum_required (VERSION 3.6)
set(GIT_REPOSITORY "https://github.com/intel/tinycrypt.git")
set(GIT_BRANCH "master")
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt)
	message(STATUS "Need to clone for the first call to cmake")
	execute_process(
		COMMAND git clone --depth 1 --branch ${GIT_BRANCH} ${GIT_REPOSITORY}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
endif()
project(tinycrypt CXX C ASM)
set(TINYCRYPT_SOURCE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt/lib/source)
set(TINYCRYPT_INCLUDE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt/lib/include/tinycrypt)
set(TINYCRYPT_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt_aes_api.c
	${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt_sha256_api.c
	${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt_api.h
	${TINYCRYPT_SOURCE_FOLDER}/aes_decrypt.c
  ${TINYCRYPT_SOURCE_FOLDER}/ccm_mode.c 
  ${TINYCRYPT_SOURCE_FOLDER}/ctr_prng.c 
  ${TINYCRYPT_SOURCE_FOLDER}/hmac_prng.c
  ${TINYCRYPT_SOURCE_FOLDER}/aes_encrypt.c 
  ${TINYCRYPT_SOURCE_FOLDER}/cmac_mode.c 
  ${TINYCRYPT_SOURCE_FOLDER}/sha256.c
  ${TINYCRYPT_SOURCE_FOLDER}/cbc_mode.c 
  ${TINYCRYPT_SOURCE_FOLDER}/ctr_mode.c 
  ${TINYCRYPT_SOURCE_FOLDER}/hmac.c 
  ${TINYCRYPT_SOURCE_FOLDER}/utils.c
  ${TINYCRYPT_INCLUDE_FOLDER}/aes.h
  ${TINYCRYPT_INCLUDE_FOLDER}/cbc_mode.h
  ${TINYCRYPT_INCLUDE_FOLDER}/ccm_mode.h
  ${TINYCRYPT_INCLUDE_FOLDER}/cmac_mode.h
  ${TINYCRYPT_INCLUDE_FOLDER}/constants.h
  ${TINYCRYPT_INCLUDE_FOLDER}/ctr_mode.h
  ${TINYCRYPT_INCLUDE_FOLDER}/ctr_prng.h
  ${TINYCRYPT_INCLUDE_FOLDER}/hmac.h
  ${TINYCRYPT_INCLUDE_FOLDER}/hmac_prng.h
  ${TINYCRYPT_INCLUDE_FOLDER}/sha256.h
  ${TINYCRYPT_INCLUDE_FOLDER}/utils.h)
if(CMSDK_IS_ARM)
	set(LIB_OPTION kernel)
endif()
cmsdk2_add_library(
	NAME ${PROJECT_NAME}
	OPTION "${LIB_OPTION}"
	CONFIG release
	ARCH ${CMSDK_ARCH}
	TARGET RELEASE_TARGET)
target_sources(${RELEASE_TARGET}
	PRIVATE
	${TINYCRYPT_SOURCES})
target_compile_definitions(${RELEASE_TARGET}
	PUBLIC
	HAVE_CONFIG_H=1
	PRIVATE
	IS_LOCAL_BUILD=1)
target_compile_options(${RELEASE_TARGET} PUBLIC ${API_PUBLIC_COMPILE_OPTIONS})
target_include_directories(${RELEASE_TARGET}
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt/lib/include>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt/lib/include
	${CMAKE_CURRENT_SOURCE_DIR})
cmsdk2_add_library(
	NAME ${PROJECT_NAME}
	OPTION "${LIB_OPTION}"
	CONFIG debug
	ARCH ${CMSDK_ARCH}
	TARGET DEBUG_TARGET)
cmsdk2_copy_target(SOURCE ${RELEASE_TARGET} DESTINATION ${DEBUG_TARGET})
target_compile_options(${DEBUG_TARGET} PUBLIC ${API_PUBLIC_DEBUG_COMPILE_OPTIONS})
cmsdk2_library_add_dependencies(
	TARGET ${DEBUG_TARGET}
	DEPENDENCIES "")
cmsdk2_library_add_dependencies(
	TARGET ${RELEASE_TARGET}
	DEPENDENCIES "")
install(DIRECTORY
	${TINYCRYPT_INCLUDE_FOLDER}
	DESTINATION include/tinycrypt)
install(FILES ${PROJECT_NAME}.cmake
	DESTINATION ${CMSDK_LOCAL_PATH}/cmake/targets)
