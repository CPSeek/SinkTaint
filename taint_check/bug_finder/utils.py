import sys
import os
from os.path import dirname, abspath

sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), './')))
import sinks

ROUND = 5

HTTP_KEYWORDS = ("boundary=", "Content-Type", "http_")
SINK_FUNCS = [('strcpy', sinks.strcpy), ('sprintf', sinks.sprintf), ('fwrite', sinks.fwrite), 
('memcpy', sinks.memcpy),('strncpy', sinks.memcpy), ('system', sinks.system),('___system', sinks.system),('bstar_system', 
sinks.system),('popen',sinks.system),('execve',sinks.execve),("doSystemCmd",sinks.doSystemCmd),
("twsystem", sinks.system),('CsteSystem', sinks.system)]
TIMEOUT_TAINT = 60 * 5
TIMEOUT_TRIES = 2
