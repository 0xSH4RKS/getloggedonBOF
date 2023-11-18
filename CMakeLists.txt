##
## this file can be ignored
##

cmake_minimum_required( VERSION 3.25 )
project( getloggedonBOF C )

set( CMAKE_C_STANDARD 11 )
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )

include_directories( common )

# source code files
set( SOURCE
        entry.c
)

#add_compile_definitions( GETLOGGEDON_TEST )
add_compile_definitions( BOF )

add_executable( getloggedon ${SOURCE} )