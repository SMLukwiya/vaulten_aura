#!/bin/sh

conan create $PWD/deps/libyaml --build=missing -pr debug
conan create $PWD/deps/picotls --build=missing -pr debug

conan install . --build=missing -pr debug
cmake --preset conan-debug