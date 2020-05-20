if (NOT WINDOWS_STORE AND NOT WINDOWS_PHONE)
    add_executable(KiteApp kiteapp.cpp)
    target_link_libraries(KiteApp cpprest)
endif()
