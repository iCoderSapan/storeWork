if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
  add_executable(oauth2kite
    Oauth2Kite.cpp
    )

  target_link_libraries(oauth2kite cpprest)
endif()
