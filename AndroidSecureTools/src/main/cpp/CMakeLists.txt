# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

include_directories(G:/AndroidProject/cryptopp)
set(cpp_dir G:/AndroidProject/cryptopp)
file(GLOB cpp_src ${cpp_dir}/*.cpp)
add_library(lib_cryptopp SHARED ${cpp_src})
set_target_properties(lib_cryptopp PROPERTIES IMPORTED_LOCATION
        G:/AndroidProject/AndroidSecureTools-AST/AndroidSecureTools/src/main/jniLibs/${ANDROID_ABI}/libcryptopp_shared.so
        LINKER_LANGUAGE CXX)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
        android-secure-tools-lib

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        native-lib.cpp
        Rsa.cpp)

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

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries(
        android-secure-tools-lib
        lib_cryptopp

        ${log-lib})