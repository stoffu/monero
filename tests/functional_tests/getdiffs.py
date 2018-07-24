#!/usr/bin/env python3

# Copyright (c) 2018 The Monero Project
# 
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

"""Test blockchain RPC calls

Test the following RPCs:
    - get_info
    - generateblocks
    - [TODO: many tests still need to be written]

"""

from test_framework.daemon import Daemon

import sys
import datetime

class GetDiffs():
    def run(self, port, start_height, end_height):
        daemon = Daemon(port=port)
        res = daemon.get_block_headers_range(start_height, end_height)
        print('var chartData = [')
        for i in range(0, end_height - start_height + 1):
            print('  { height:', (start_height + i),
                ', difficulty:', res['headers'][i]['difficulty'],
                ', date:', datetime.datetime.fromtimestamp(int(res['headers'][i]['timestamp'])).strftime('\"%Y-%m-%d %H:%M:%S\"'),
                ', num_txes:', res['headers'][i]['num_txes'],
                ', reward:', float(("%0.12f" % (float(res['headers'][i]['reward']) * (0.00000000001 if port == 34568 else 0.000000000001)))),
                ', block_size:', res['headers'][i]['block_size'],
                '},')
        print(']')

if __name__ == '__main__':
    GetDiffs().run(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
