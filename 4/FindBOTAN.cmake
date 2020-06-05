include(FindPkgConfig)

if (NOT BOTAN_FOUND)
    pkg_check_modules(BOTAN botan-2)
endif ()

if (NOT BOTAN_FOUND)
    find_path(BOTAN_INCLUDE_DIRS NAMES botan/botan.h PATH_SUFFIXES botan-2)

    find_library(BOTAN_LIBRARIES NAMES botan botan-2)

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(BOTAN REQUIRED_VARS BOTAN_LIBRARIES BOTAN_INCLUDE_DIRS)

    if (BOTAN_FOUND)
        set(BOTAN_LIBRARY ${BOTAN_LIBRARIES} CACHE INTERNAL "")
        set(BOTAN_INCLUDE_DIR ${BOTAN_INCLUDE_DIRS} CACHE INTERNAL "")
        set(BOTAN_FOUND ${BOTAN_FOUND} CACHE INTERNAL "")
    endif ()
endif ()

mark_as_advanced(BOTAN_INCLUDE_DIRS BOTAN_LIBRARIES)
