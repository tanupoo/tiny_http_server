try:
    from .chunkable_http_server import ChunkableHTTPRequestHandler
    from .tiny_http_server import TinyHTTPHandler, ThreadedHTTPServer, TinyHTTPServer, DEBUG2, DEBUG3
except:
    from chunkable_http_server import ChunkableHTTPRequestHandler
    from tiny_http_server import TinyHTTPHandler, ThreadedHTTPServer, TinyHTTPServer, DEBUG2, DEBUG3
