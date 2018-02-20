# Copyright (c) 2014-2017, The Monero Project
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

MESSAGE(STATUS "Looking for libpcsclite")

include(FindPkgConfig)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_PCSC QUIET libpcsclite)
endif()

find_path(PCSC_INCLUDE_DIR pcsclite.h WinSCard.h
    HINTS ${PC_PCSC_INCLUDEDIR} ${PC_PCSC_INCLUDE_DIRS}
    PATH_SUFFIXES PCSC)

find_library(PCSC_LIBRARY NAMES PCSC WinSCard pcsclite 
    HINTS ${PC_PCSC_LIBDIR} ${PC_PCSC_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCSC DEFAULT_MSG PCSC_LIBRARY PCSC_INCLUDE_DIR)

set(LIBPCSC_LIBRARY_DIRS ${PC_PCSC_LIBRARY_DIRS})
set(LIBPCSC_INCLUDE ${PCSC_INCLUDE_DIR})

#mark_as_advanced(PCSC_INCLUDE_DIR PCSC_LIBRARY)
