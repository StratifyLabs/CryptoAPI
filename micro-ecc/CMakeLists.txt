cmake_minimum_required(VERSION 3.6)
set(GIT_REPOSITORY "https://github.com/kmackay/micro-ecc.git")
set(GIT_BRANCH "master")
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc)
  message(STATUS "Need to clone for the first call to cmake")
  execute_process(
    COMMAND git clone --depth 1 --branch ${GIT_BRANCH} ${GIT_REPOSITORY}
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
cmsdk2_add_library(
  NAME ${PROJECT_NAME}
  OPTION "${LIB_OPTION}"
  CONFIG release
  ARCH ${CMSDK_ARCH}
  TARGET RELEASE_TARGET)
target_sources(${RELEASE_TARGET}
  PRIVATE
  ${UECC_SOURCES})
target_compile_definitions(${RELEASE_TARGET}
  PUBLIC
  HAVE_CONFIG_H=1
  PRIVATE
  IS_LOCAL_BUILD=1)
target_compile_options(${RELEASE_TARGET} PUBLIC ${API_PUBLIC_COMPILE_OPTIONS})
target_include_directories(${RELEASE_TARGET}
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/micro-ecc
  ${CMAKE_CURRENT_SOURCE_DIR})
cmsdk2_add_library(
  NAME ${PROJECT_NAME}
  OPTION "${LIB_OPTION}"
  CONFIG debug
  ARCH ${CMSDK_ARCH}
  TARGET DEBUG_TARGET)
cmsdk2_copy_target(
  SOURCE ${RELEASE_TARGET}
  DESTINATION ${DEBUG_TARGET})
target_compile_options(${DEBUG_TARGET} PUBLIC ${API_PUBLIC_DEBUG_COMPILE_OPTIONS})
if(CMSDK_IS_ARM)
  cmsdk2_library_add_dependencies(
    TARGET ${RELEASE_TARGET}
    DEPENDENCIES StratifyOS_interface)
  cmsdk2_library_add_dependencies(
    TARGET ${DEBUG_TARGET}
    DEPENDENCIES StratifyOS_interface)
endif()
if(CMSDK_IS_LINUX)
  target_link_libraries(${DEBUG_TARGET} PRIVATE bsd)
  target_link_libraries(${RELEASE_TARGET} PRIVATE bsd)
endif()
install(FILES ${PROJECT_NAME}.cmake
  DESTINATION ${CMSDK_LOCAL_PATH}/cmake/targets)
