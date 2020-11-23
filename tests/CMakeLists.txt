

set(DEPENDENCIES TestAPI FsAPI CryptoAPI)

api_add_test_executable(${PROJECT_NAME} 32768 "${DEPENDENCIES}")



