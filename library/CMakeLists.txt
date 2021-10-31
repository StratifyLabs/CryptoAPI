
set(LIBRARIES VarAPI FsAPI InetAPI)
if (SOS_IS_LINK)
  set(LIBRARIES uECC ${LIBRARIES})
endif ()
api_add_api_library(${PROJECT_NAME} "${LIBRARIES}")
