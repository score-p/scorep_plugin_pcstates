project(pcstate)

cmake_minimum_required(VERSION 2.8)

#plugin source files
set(PLUGIN_SOURCE pc_state_plugin.c)

#Input Options
option(X86A_STATIC "Link x86_adapt library static." ON)
option(X86A_DIR "Path to libx86_adapt directory" "")
option(X86A_INC "Path to libx86_adapt headers" "")
option(X86A_LIB "Path to libx86_adapt" "")

#Input Options
option(MSR_STATIC "Link msr library static." ON)
option(MSR_DIR "Path to libmsr directory" "")
option(MSR_INC "Path to libmsr headers" "")
option(MSR_LIB "Path to libmsr" "")

#additional c flags
set(CMAKE_C_FLAGS "-D_GNU_SOURCE -std=gnu99")

#debugging c flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -Wstrict-prototypes -Wall -Wundef -Wno-long-long -Wsign-compare -Wcomment -pedantic -finline-functions -fno-strict-aliasing")
set(CMAKE_C_FLAGS_RELEASE "-Os")


message(STATUS "Trying to find Score-P")
include(common/FindScorep.cmake)
if(SCOREP_FOUND)
    include_directories(${SCOREP_INCLUDE_DIRS})    
    link_directories(${SCOREP_LIBRARY_DIRS})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DSCOREP")
    SET(CMAKE_INSTALL_PREFIX ${SCOREP_ROOT_PATH} CACHE PATH "Install path prefix, prepended onto install directories." FORCE)
endif()

message(STATUS "Trying to find VampirTrace")
include(common/FindVampirTrace.cmake)
if(VT_FOUND)
    include_directories(${VT_INCLUDE_DIRS})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVT")
    SET(CMAKE_INSTALL_PREFIX ${VT_ROOT_PATH} CACHE PATH "Install path prefix, prepended onto install directories." FORCE)
endif()


if(NOT SCOREP_FOUND AND NOT VT_FOUND)
	message(SEND_ERROR "Neither Score-P, nor VampirTrace found. One of them is required!")
endif()

if(X86A_STATIC)
	set(LIBX86A_NAME libx86_adapt_static.a)
else()
	set(LIBX86A_NAME libx86_adapt.so)
endif()
	
include(common/FindX86Adapt.cmake)
if(X86_ADAPT_FOUND)

    include_directories(${X86_ADAPT_INC_DIR})    
    link_directories(${X86_ADAPT_LIB_DIR})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DX86_ADAPT")
	set(USED_LIB_NAME ${LIBX86A_NAME})
	
else()

	message(STATUS "Could NOT find libx86_adapt, trying to find libmsr")
	
	if(MSR_STATIC)
		set(LIBMSR_NAME libmsr_static.a)
	else()
		set(LIBMSR_NAME libmsr.so)
	endif()
	
	include(common/FindMSR.cmake)
	
	if(MSR_FOUND)
	    include_directories(${MSR_INC_DIR})    
	    link_directories(${MSR_LIB_DIR})
		message(STATUS "Using ${MSR_LIB_DIR}")
		set(USED_LIB_NAME ${LIBMSR_NAME})
	else()
	    message(SEND_ERROR "Neither libx86_adapt, nor libmsr found. One of them is required!")
	endif()
endif()

message(STATUS "Using ${USED_LIB_NAME}")

add_library(${PROJECT_NAME} SHARED ${PLUGIN_SOURCE})

target_link_libraries(${PROJECT_NAME} ${USED_LIB_NAME} pthread m)
