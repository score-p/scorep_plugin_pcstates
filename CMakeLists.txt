cmake_minimum_required(VERSION 2.8)
project(pcstates_plugin)

option(X86A_STATIC "Link x86_adapt library static." ON)
option(X86A_DIR "Path to libx86_adapt directory" "")
option(X86A_INC "Path to libx86_adapt headers" "")
option(X86A_LIB "Path to libx86_adapt" "")
option(MSR_STATIC "Link msr library static." ON)
option(MSR_DIR "Path to libmsr directory" "")
option(MSR_INC "Path to libmsr headers" "")
option(MSR_LIB "Path to libmsr" "")
option(BACKEND_SCOREP "Build plugin using scorep(ON) or vampirtrace(OFF)" ON)

set(SCOREP_FOUND false)

set(PLUGIN_SOURCE pc_state_plugin.c)


if(BACKEND_SCOREP)
    include(common/FindScorep.cmake)
    if(SCOREP_FOUND)
        include_directories(${SCOREP_INCLUDE_DIRS})
        link_directories(${SCOREP_LIBRARY_DIRS})
        add_definitions("-DSCOREP")
    else()
        message("Score-P was not found, falling back to VampirTrace!")
    endif()
endif()


if(NOT BACKEND_SCOREP OR NOT SCOREP_FOUND)
    include(common/FindVampirTrace.cmake)
    if(VT_FOUND)
        include_directories(${VT_INCLUDE_DIRS})
        add_definitions("-DVT")
    else()
        message(SEND_ERROR "Found neither Score-P nor VampirTrace backend!")
    endif()
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
    add_definitions("-DX86_ADAPT")
    set(USED_LIB_NAME ${LIBX86A_NAME})
else()
    message("Could NOT find libx86_adapt, trying to find libmsr")
    if(MSR_STATIC)
        set(LIBMSR_NAME libmsr_static.a)
    else()
        set(LIBMSR_NAME libmsr.so)
    endif()


    include(common/FindMSR.cmake)
    if(MSR_FOUND)
        include_directories(${MSR_INC_DIR})
        link_directories(${MSR_LIB_DIR})
        set(USED_LIB_NAME ${LIBMSR_NAME})
    else()
        message(SEND_ERROR "Neither libx86_adapt, nor libmsr found.")
    endif()
endif()


#additional c flags
set(CMAKE_C_FLAGS "-D_GNU_SOURCE -std=gnu99")
#debugging c flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -Wstrict-prototypes -Wall -Wundef -Wno-long-long -Wsign-compare -Wcomment -pedantic -finline-functions -fno-strict-aliasing")
#release c flags
set(CMAKE_C_FLAGS_RELEASE "-Os")

add_library(${PROJECT_NAME} SHARED ${PLUGIN_SOURCE})
target_link_libraries(${PROJECT_NAME} ${USED_LIB_NAME} pthread m)

install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION lib)
