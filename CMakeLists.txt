cmake_minimum_required(VERSION 3.16)
project(ftp_recover LANGUAGES CXX)

add_executable(ftp-recover main.cpp)
target_compile_features(ftp-recover PRIVATE cxx_std_17)
target_compile_options(ftp-recover PRIVATE -Wall -Wextra -Wpedantic)
