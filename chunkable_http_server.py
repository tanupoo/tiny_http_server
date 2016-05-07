#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Shoichi Sakane <sakane@tanu.org>, All rights reserved.
# See the file LICENSE in the top level directory for more details.
#

from __future__ import print_function

import sys
import argparse
import traceback
import json

from tiny_http_server import ThreadedHTTPServer, TinyHTTPHandler, TinyHTTPServer

'''
- Chunk handling referred to "4.1.  Chunked Transfer Coding in RFC 7230".
- As for the processing of 'Connection: close' and 'Connection: Keep-Alive',
  this class doesn't support persistent connection.
  i.e. it always replies with 'connection: close'.
'''

'''
4.1 Chunked Transfer Coding

 chunked-body   = *chunk
                  last-chunk
                  trailer-part
                  CRLF

 chunk          = chunk-size [ chunk-ext ] CRLF
                  chunk-data CRLF
 chunk-size     = 1*HEXDIG
 last-chunk     = 1*("0") [ chunk-ext ] CRLF

 chunk-data     = 1*OCTET ; a sequence of chunk-size octets
'''

__version__ = '0.1'

class ChunkableHTTPRequestHandler(TinyHTTPHandler):

    max_content_size = 512*1024  # 512KB
    force_chunked = False
    chunk_max_size = 512
    chunk_header_length = 128    # chunk header length of inline or footer
    chunk_tail_buffer = 16
    chunk_read_timeout = 5

    def __init__(self, request, client_address, server, **kwargs):
        if kwargs.has_key('force_chunked'):
            if kwargs['force_chunked'] in [ True, False ]:
                self.force_chunked = kwargs['force_chunked']
            else:
                raise ValueError('invalid value of force_chunked')
        if kwargs.has_key('chunk_max_size'):
            if kwargs['chunk_max_size'] > 0:
                self.chunk_max_size = kwargs['chunk_max_size']
            else:
                raise ValueError('invalid value of chunk_max_size')
        if kwargs.has_key('chunk_read_timeout'):
            if kwargs['chunk_read_timeout'] > 0:
                self.chunk_read_timeout = kwargs['chunk_read_timeout']
            else:
                raise ValueError('invalid value of chunk_read_timeout')
        TinyHTTPHandler.__init__(self, request, client_address, server)
        self.set_server_version('ChunkableHTTPServer/' + __version__)

    def do_PUT(self):
        pass

    def read_content(self):
        transfer_encoding = self.headers.get('Transfer-Encoding')
        if transfer_encoding:
            if transfer_encoding == 'chunked':
                self.read_chunked()
            else:
                print('ERROR: not supported such transfer_encoding',
                      transfer_encoding)
        elif self.headers.has_key('Content-Length'):
            self.post_read(self.read_length())
        else:
            if self.server.config['debug_level']:
                print('DEBUG: Content-Length or Transfer-Encoding are not specified.')
            self.post_read(self.read_somehow())

    def read_chunked(self):
        transfer_encoding = self.headers.get('Transfer-Encoding')
        if transfer_encoding != 'chunked':
            raise RuntimeError()
        t = threading.Thread(target=self.__read_chunked)
        t.start()
        t.join(self.chunk_read_timeout)
        if t.is_alive() == True:
            print('WARNING: timed out of thread of reading chunks.')

    def __read_chunked(self):
        total_length = 0
        contents = []
        while True:
            try:
                #
                # read the 1st line of a chunk.
                #     i.e. chunk-size [ chunk-ext ] CRLF
                # chunk_header_length bytes is enough to read the chunk header.
                #
                chunk_header = self.rfile.readline(self.chunk_header_length)
                if self.server.config['debug_level']:
                    print('DEBUG: chunk header=', chunk_header)
                if chunk_header == '\r\n':
                    if self.server.config['debug_level']:
                        print('DEBUG: last-chunk does not exist.')
                        print('DEBUG: stop reading chunks anyway.')
                    chunk_size = 0
                    break
                if not chunk_header:
                    raise RuntimeError('Connection reset by peer')
                chunk_size_string = chunk_header.split(';', 1)[0]
                chunk_size = int(chunk_size_string, 16)
            except:
                raise
            if chunk_size == 0:
                if self.server.config['debug_level']:
                    print('DEBUG: last-chunk has been found.')
                break
            #
            # read a chunk
            #   don't use readline() because CR or LF may be among the chunk.
            #
            chunk = self.rfile.read(chunk_size)
            if self.server.config['debug_level']:
                print('DEBUG: chunked size=', chunk_size)
                print('DEBUG: chunk=', chunk)
                if self.server.config['debug_level'] > 1:
                    print('DEBUG: chunk(hex)=',
                          [hex(x) for x in bytearray(chunk)])
            # remove the tail.
            nl = self.rfile.read(2)
            if self.server.config['debug_level']:
                print('DEBUG: tail of chunk=', [hex(x) for x in bytearray(nl)])
            #
            contents.append(chunk)
            total_length += chunk_size
            if total_length > self.max_content_size:
                raise ValueError('too large content > %d' %
                                 self.max_content_size)
        # cool down
        # XXX just skip the footer and CR+LF in the end.
        while True:
            try:
                footer = self.rfile.readline(self.chunk_header_length)
                if self.server.config['debug_level']:
                    print('DEBUG: footer=', footer)
                if footer == '\r\n':
                    if self.server.config['debug_level']:
                        print('DEBUG: end of chunk has been found.')
                    break
                elif not footer:
                    raise RuntimeError('Connection reset by peer')
            except:
                raise
        self.post_read(contents)

    def read_somehow(self):
        '''
        may be overriddedn.
        '''
        self.post_read([])

    def send_chunked(self, code, msg_list, content_type):
        self.send_response(code)
        #self.send_header('Content-Type', content_type)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Connection', 'close')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        if self.server.config['debug_level'] > 1:
            print('---BEGIN OF RESPONSE---')
        for c in msg_list:
            s = self.chunk_max_size
            bl = len(c) / s + (1 if len(c) % s else 0)
            c_frag = [ c[x * s : x * s + s] for x in range(bl) ]
            for i in c_frag:
                chunk_size = hex(len(i))[2:]
                self.wfile.write(''.join([ chunk_size, '\r\n', i, '\r\n' ]))
                if self.server.config['debug_level'] > 1:
                    print(chunk_size)
                    print(i.strip(), '\n')
                    if self.server.config['debug_level'] > 2:
                        print('hex=', [ hex(x)[2:] for x in bytearray(i) ],
                              '\n')
        if self.server.config['debug_level'] > 1:
            print('---END OF RESPONSE---')
        self.wfile.write('0\r\n')
        self.wfile.write('\r\n')
        # 
        self.send_header('Connection', 'close')

'''
test
'''
if __name__ == '__main__':
    httpd = TinyHTTPServer(ChunkableHTTPRequestHandler)
    httpd.run()
