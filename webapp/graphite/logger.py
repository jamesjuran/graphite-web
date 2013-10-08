"""Copyright 2008 Orbitz WorldWide

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

import os, logging
from logging.handlers import TimedRotatingFileHandler as Rotater
from django.conf import settings

class NullHandler(logging.Handler):
  """
  A log handler that does nothing. Part of logging.Handlers in python 2.7,
  but defined here for  python 2.6 compatibility.
  """
  def emit(self, record):
    pass


class UTFFixedSysLogHandler(logging.handlers.SysLogHandler):
  """
  A bug-fix sub-class of SysLogHandler that fixes the UTF-8 BOM syslog
  bug that caused UTF syslog entries to not go to the correct
  facility.  This is fixed by over-riding the 'emit' definition
  with one that puts the BOM in the right place (after prio, instead
  of before it).

  Based on Python 2.7 version of logging.handlers.SysLogHandler.

  Bug Reference: http://bugs.python.org/issue7077

  Purportedly fixed in an upcoming RHEL update-
  https://bugzilla.redhat.com/show_bug.cgi?id=845802
  """

  def emit(self, record):
    """
    Emit a record.

    The record is formatted, and then sent to the syslog server.  If
    exception information is present, it is NOT sent to the server.
    """
    msg = self.format(record) + '\000'
    """
    We need to convert record level to lowercase, maybe this will
    change in the future.
    """
    prio = '<%d>' % self.encodePriority(self.facility,
                            self.mapPriority(record.levelname))
    if type(msg) is unicode:
      msg = msg.encode('utf-8')
    msg = prio + msg
    try:
      if self.unixsocket:
        try:
          self.socket.send(msg)
        except socket.error:
          self.socket.close()
          self._connect_unixsocket(self.address)
          self.socket.send(msg)
      elif self.socktype == socket.SOCK_DGRAM:
        self.socket.sendto(msg, self.address)
      else:
        self.socket.sendall(msg)
    except (KeyboardInterrupt, SystemExit):
      raise
    except:
      self.handleError(record)


class GraphiteLogger:
  def __init__(self):
    self.nullHandler = NullHandler()
    #Setup loggers
    self.infoLogger = logging.getLogger("info")
    self.exceptionLogger = logging.getLogger("exception")
    self.cacheLogger = logging.getLogger("cache")
    if not self.cacheLogger.handlers:
        self.cacheLogger.addHandler(self.nullHandler)
    self.renderingLogger = logging.getLogger("rendering")
    if not self.renderingLogger.handlers:
        self.renderingLogger.addHandler(self.nullHandler)
    self.metricAccessLogger = logging.getLogger("metric_access")
    if not self.metricAccessLogger.handlers:
        self.metricAccessLogger.addHandler(self.nullHandler)

  def info(self,msg,*args,**kwargs):
    return self.infoLogger.info(msg,*args,**kwargs)

  def exception(self,msg="Exception Caught",**kwargs):
    return self.exceptionLogger.exception(msg,**kwargs)

  def cache(self,msg,*args,**kwargs):
    return self.cacheLogger.info(msg,*args,**kwargs)

  def rendering(self,msg,*args,**kwargs):
    return self.renderingLogger.info(msg,*args,**kwargs)

  def metric_access(self,msg,*args,**kwargs):
    return self.metricAccessLogger.info(msg,*args,**kwargs)


log = GraphiteLogger() # import-shared logger instance

# Test program
if __name__ == '__main__':
  handler = UTFFixedSysLogHandler(address="/dev/log",facility=logging.handlers.SysLogHandler.LOG_LOCAL3)
  testLogger = logging.getLogger("test")
  testLogger.setLevel(logging.INFO)
  testLogger.addHandler(handler)
  testLogger.info("test message")
  print "Sent test message to syslog"
