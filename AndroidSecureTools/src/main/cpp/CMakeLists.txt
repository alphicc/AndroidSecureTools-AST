# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

set(PROJECT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../../../)

include(AndroidNdkModules)

add_library(libcrypto STATIC IMPORTED)
set_target_properties(libcrypto PROPERTIES IMPORTED_LOCATION
        ${PROJECT_PATH}/AndroidSecureTools/src/main/jniLibs/${ANDROID_ABI}/libcrypto.a)

add_library(libssl STATIC IMPORTED)
set_target_properties(libssl PROPERTIES IMPORTED_LOCATION
        ${PROJECT_PATH}/AndroidSecureTools/src/main/jniLibs/${ANDROID_ABI}/libssl.a)


# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
file(GLOB AES CONFIGURE_DEPENDS "aes/*.h" "aes/*.cpp")
file(GLOB UTILS CONFIGURE_DEPENDS "utils/*.h" "utils/*.cpp")
file(GLOB HASH CONFIGURE_DEPENDS "hash/*.h" "hash/*.cpp")

add_library( # Sets the name of the library.
        android-secure-tools-lib

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        RsaInteractor.cpp
        Rsa.cpp

        #aes/aesInteractor.cpp
        #aes.cpp
        
        ${AES}
        ${UTILS}
        ${HASH}
        #aes/aesKeyGenResult.cpp
        #aes/aesKeyGenResult.cpp
        #/aes/aesKeyGenResult.cpp
        #/aes/aesKeyGenResult.h

        #Utils.cpp
        )
#add_library(android-secure-tools-lib SHARED ${AES})

##include_directories(/aes/)
##add_library(
##        android-secure-tools-lib
##
##        SHARED
##
##        /aes/aesKeyGenResult.cpp)

# AES
#add_library(
#        android-secure-tools-lib
#        SHARED
#        aes/aesKeyGenResult.cpp
#        #/aes/aesKeyGenResult.h
#)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

target_include_directories(android-secure-tools-lib PRIVATE
        ${PROJECT_PATH}/AndroidSecureTools/include)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries(
        android-secure-tools-lib
        libcrypto
        libssl

        ${log-lib})