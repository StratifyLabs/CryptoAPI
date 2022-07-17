cmake_minimum_required(VERSION 3.6)

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
set(UECC_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/micro_ecc_api.c
  ${CMAKE_CURRENT_SOURCE_DIR}/micro_ecc_api.h
  ${SOURCE_FOLDER}/uECC.c
  ${INCLUDE_FOLDER}/uECC.h
  ${INCLUDE_FOLDER}/uECC_vli.h
  ${INCLUDE_FOLDER}/types.h
  )

if(CMSDK_IS_ARM)
  set(LIB_OPTION kernel)
endif()

cmsdk_library_target(RELEASE ${PROJECT_NAME} "${LIB_OPTION}" release ${CMSDK_ARCH})

add_library(${RELEASE_TARGET} STATIC)

target_sources(${RELEASE_TARGET}
  PRIVATE
  ${UECC_SOURCES}
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

cmsdk_library_target(DEBUG ${PROJECT_NAME} "${LIB_OPTION}" debug ${CMSDK_ARCH})
add_library(${DEBUG_TARGET} STATIC)
cmsdk_copy_target(${RELEASE_TARGET} ${DEBUG_TARGET})
cmsdk_library_add_arch_targets("${DEBUG_OPTIONS}" ${CMSDK_ARCH} "")

if(CMSDK_IS_LINUX)
  target_link_libraries(${DEBUG_TARGET} PRIVATE bsd)
  target_link_libraries(${RELEASE_TARGET} PRIVATE bsd)
endif()

cmsdk_library_add_arch_targets("${RELEASE_OPTIONS}" ${CMSDK_ARCH} "")

install(FILES ${PROJECT_NAME}.cmake
  DESTINATION ${CMSDK_LOCAL_PATH}/cmake/targets)
