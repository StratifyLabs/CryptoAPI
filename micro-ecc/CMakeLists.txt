cmake_minimum_required (VERSION 3.6)

if(NOT SOS_SDK_PATH)
	set(SOS_SDK_PATH $ENV{SOS_SDK_PATH})
endif()

set(CMAKE_MODULE_PATH ${SOS_SDK_PATH}/cmake)
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_MODULE_PATH}/sos-toolchain.cmake)
include(sos-sdk)

set(GIT_REPOSITORY "https://github.com/kmackay/micro-ecc.git")
set(GIT_BRANCH "master")
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc)
	message(STATUS "Need to clone for the first call to cmake")
	execute_process(
		COMMAND git clone --branch ${GIT_BRANCH} ${GIT_REPOSITORY}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
endif()

project(uECC CXX C ASM)

set(SOURCE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc)
set(INCLUDE_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc)
set(TINYCRYPT_SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/micro_ecc_api.c
	${CMAKE_CURRENT_SOURCE_DIR}/micro_ecc_api.h
	${SOURCE_FOLDER}/uECC.c
	${INCLUDE_FOLDER}/uECC.h
	${INCLUDE_FOLDER}/uECC_vli.h
	${INCLUDE_FOLDER}/types.h
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
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc>
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc
	${CMAKE_CURRENT_SOURCE_DIR}
	)

sos_sdk_library_target(DEBUG ${PROJECT_NAME} "${LIB_OPTION}" debug ${SOS_ARCH})
add_library(${DEBUG_TARGET} STATIC)
sos_sdk_copy_target(${RELEASE_TARGET} ${DEBUG_TARGET})
sos_sdk_library_add_arch_targets("${DEBUG_OPTIONS}" ${SOS_ARCH} "")

if(SOS_IS_LINK)
	sos_sdk_library_target(COVERAGE ${PROJECT_NAME} "${LIB_OPTION}" coverage ${SOS_ARCH})
	add_library(${COVERAGE_TARGET} STATIC)
	sos_sdk_copy_target(${RELEASE_TARGET} ${COVERAGE_TARGET})
	sos_sdk_library_add_arch_targets("${COVERAGE_OPTIONS}" ${SOS_ARCH} "")
endif()

sos_sdk_library_add_arch_targets("${RELEASE_OPTIONS}" ${SOS_ARCH} "")


install(FILES ${PROJECT_NAME}.cmake
	DESTINATION ${SOS_SDK_PATH}/cmake/targets)
