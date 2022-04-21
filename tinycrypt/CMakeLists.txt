cmake_minimum_required (VERSION 3.6)

if(NOT SOS_SDK_PATH)
	set(SOS_SDK_PATH $ENV{SOS_SDK_PATH})
endif()

set(CMAKE_MODULE_PATH ${SOS_SDK_PATH}/cmake)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_MODULE_PATH}/sos-toolchain.cmake)
include(sos-sdk)

set(GIT_REPOSITORY "https://github.com/intel/tinycrypt.git")
set(GIT_BRANCH "master")
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt)
	message(STATUS "Need to clone for the first call to cmake")
	execute_process(
		COMMAND git clone --branch ${GIT_BRANCH} ${GIT_REPOSITORY}
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
  ${TINYCRYPT_INCLUDE_FOLDER}/utils.h
)


if(SOS_IS_ARM)
	set(LIB_OPTION kernel)
endif()

sos_sdk_library_target(RELEASE ${PROJECT_NAME} "${LIB_OPTION}" release ${SOS_ARCH})

add_library(${RELEASE_TARGET} STATIC)

target_sources(${RELEASE_TARGET}
	PRIVATE
	${TINYCRYPT_SOURCES}
	)

target_compile_definitions(${RELEASE_TARGET}
	PUBLIC
	HAVE_CONFIG_H=1
	PRIVATE
	IS_LOCAL_BUILD=1
	)

target_compile_options(${RELEASE_TARGET}
	PUBLIC
	-Os
	)

target_include_directories(${RELEASE_TARGET}
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt/lib/include>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/tinycrypt/lib/include
	${CMAKE_CURRENT_SOURCE_DIR}
	)

sos_sdk_library_target(DEBUG ${PROJECT_NAME} "${LIB_OPTION}" debug ${SOS_ARCH})
add_library(${DEBUG_TARGET} STATIC)
sos_sdk_copy_target(${RELEASE_TARGET} ${DEBUG_TARGET})
sos_sdk_library_add_arch_targets("${DEBUG_OPTIONS}" ${SOS_ARCH} "")
sos_sdk_library_add_arch_targets("${RELEASE_OPTIONS}" ${SOS_ARCH} "")

install(DIRECTORY
	${TINYCRYPT_INCLUDE_FOLDER}
	DESTINATION include/tinycrypt)

install(FILES ${PROJECT_NAME}.cmake
	DESTINATION ${SOS_SDK_PATH}/cmake/targets)
