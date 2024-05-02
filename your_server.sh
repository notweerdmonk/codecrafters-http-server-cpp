#!/bin/sh
#
# DON'T EDIT THIS!
#
# CodeCrafters uses this file to test your code. Don't make any changes here!
#
# DON'T EDIT THIS!
set -e
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug .. >/dev/null
make >/dev/null
exec ./server "$@"
