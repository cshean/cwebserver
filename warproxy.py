#!/usr/bin/env python3
import asyncore
from collections import namedtuple
import http.client
import logging
import logging.handlers
import os
import socket
import subprocess
import sys
import time


# Trivial type describing queued-attackers
AttackQueue = namedtuple("AttackQueue", ["start", "attacker", "queue"])

class AttackTurnstile:
    '''Data structure for managing multiple parallel AttackQueues (i.e., a meta-queue).'''
    
    log = logging.getLogger("umpire")   # Part of the "umpire" set of logic
    
    def __init__(self):
        self._src_map = {}

    def enqueue_conn(self, attacker, conn, timestamp=None):
        '''Stick an incoming connection into the appropriate queue (possibly creating one).'''
        if timestamp is None:
            timestamp = time.time()

        try:
            self._src_map[attacker].queue.append(conn)
        except KeyError:
            self._src_map[attacker] = AttackQueue(timestamp, attacker, [conn])

    def drop_conn(self, attacker, conn) -> bool:
        '''Remove a connection from a queued attacker's connection queue.

        If that was the queued attacker's last connection, remove that attacker from the meta-queue
        and return True; otherwise, return False.'''
        try:
            self._src_map[attacker].queue.remove(conn)
            if not self._src_map[attacker].queue:
                del self._src_map[attacker]
                return True
            else:
                return False
        except KeyError:
            self.log.error("Error dropping connection: no such attacker [{0}]".format(attacker))
        except ValueError:
            self.log.error("Error dropping connection from attacker [{0}]: connection was never queued".format(attacker))

    def dequeue_conns(self) -> tuple:
        '''Remove the oldest AttackQueue from the meta-queue and return its data to the caller.'''
        aq = min(self._src_map.values())
        del self._src_map[aq.attacker]
        return (aq.attacker, aq.queue)

def test_AttackTurnstile():
    ats = AttackTurnstile()
    ats.enqueue_conn("alice", "a1", 1)
    ats.enqueue_conn("bob", "b1", 1)
    ats.enqueue_conn("alice", "a2", 2)
    ats.enqueue_conn("bob", "b2", 2)
    ats.enqueue_conn("dave", "d1", 9)   # Out of order!
    ats.enqueue_conn("bob", "b3", 5)
    ats.enqueue_conn("alice", "a3", 7)
    ats.enqueue_conn("carol", "c1", 8)

    a, q = ats.dequeue_conns()
    assert a == "alice"
    assert q == ["a1", "a2", "a3"]

    a, q = ats.dequeue_conns()
    assert a == "bob"
    assert q == ["b1", "b2", "b3"]

    a, q = ats.dequeue_conns()
    assert a == "carol"
    assert q == ["c1"]
    
    a, q = ats.dequeue_conns()
    assert a == "dave"
    assert q == ["d1"]

    ats2 = AttackTurnstile()
    ats2.enqueue_conn("bob", "b1", 1)
    ats2.enqueue_conn("alice", "a1", 2)
    ats2.enqueue_conn("alice", "a2", 3)
    gone = ats2.drop_conn("alice", "a1")
    assert not gone
    gone = ats2.drop_conn("bob", "b1")
    assert gone
    a, q = ats2.dequeue_conns()
    assert a == "alice"
    assert q == ["a2"]


class AttackUmpire:
    '''Renders decisions on what proxy connections to forward, queue, or forceably close.

    Maintains the rules of the turnstile-attacker-proxy concept.

    Expects all connections to be "proxy dispatchers" with the following:

    * .forward() method: connect through to target
    * .close() method: shut down [both halves of] the connection
    * .attacker property: string used to identify source of connection
    '''
    
    log = logging.getLogger("umpire")
    
    def __init__(self, judge, time_limit: float = 1.0):
        self._judge = judge
        self._time_limit = time_limit
        self._ats = AttackTurnstile()
        self._cur = None

    def _reset_cur(self, timestamp):
        '''Helper to reset the "current attacker" tracker.

        If there is a "next-queued-attacker" waiting at the turnstile, make it
        the "current attacker" and ".forward()" all of its queued dispatchers.
        Otherwise, leave "current attacker" as None.
        '''
        self._cur = None
        try:
            next_attacker, next_queue = self._ats.dequeue_conns()
        except ValueError:
            self.log.debug("no new attacker (at the moment)")
        else:
            self.log.info("new attacker [{0}] starting at {1} with {2} queued connections".format(next_attacker, timestamp, len(next_queue)))
            self._cur = AttackQueue(timestamp, next_attacker, next_queue)
            for c in next_queue:
                c.forward()

    def heartbeat(self, current_time=None) -> tuple:
        '''Check whether its time to boot any current attacker and replace with the next one.

        Invokes ".close()" on any dispatchers that need to be interrupted.
        Invokes ".forward()" on any queued dispatchers that need to start relaying traffic.
        '''
        if self._cur is None:
            return
        
        if current_time is None:
            current_time = time.time()

        if (self._cur.start + self._time_limit) <= current_time:
            self.log.warning("[{0}] exceeded attack timelimit ({1}); dropping {2} connections...".format(self._cur.attacker, self._time_limit, len(self._cur.queue)))
            for c in self._cur.queue:
                c.close()
            if self._judge:
                self._judge.notify_attack_ended(self._cur.attacker, timed_out=True)
            self._reset_cur(current_time)

    def handle_closed(self, dispatcher, current_time=None) -> list:
        '''In response to an external "this dispatcher is closed" signal, remove it from the current attacker queue.
       
        If, as a result, the current attacker queue becomes empty, reset the current attacker (which may release
        queued connections to be forwarded).
        '''
        if current_time is None:
            current_time = time.time()

        if (self._cur is not None) and (self._cur.attacker == dispatcher.attacker):
            self._cur.queue.remove(dispatcher)
            if len(self._cur.queue) == 0:
                self.log.info("[{0}]'s last open connection closed; resetting current attacker".format(self._cur.attacker))
                if self._judge:
                    self._judge.notify_attack_ended(self._cur.attacker, timed_out=False)
                self._reset_cur(current_time)
        else:
            last_conn = self._ats.drop_conn(dispatcher.attacker, dispatcher)
            if last_conn:
                self.log.info("[{0}]'s last queued connection closed; removing from attacker meta-queue".format(dispatcher.attacker))

    def handle_accepted(self, dispatcher, current_time=None):
        '''Either .forwards() or queues a new dispatcher.'''
        if current_time is None:
            current_time = time.time()

        if self._cur is None:
            self.log.info("new attacker [{0}] starting at {1} with its first connection".format(dispatcher.attacker, current_time))
            self._cur = AttackQueue(current_time, dispatcher.attacker, [dispatcher])
            dispatcher.forward()
        elif dispatcher.attacker == self._cur.attacker:
            self.log.info("[{0}] is piling on with another connection".format(dispatcher.attacker))
            self._cur.queue.append(dispatcher)
            dispatcher.forward()
        else:
            self.log.info("new connection from would-be attacker [{0}] getting queued until [{1}] is done".format(dispatcher.attacker, self._cur.attacker))
            self._ats.enqueue_conn(dispatcher.attacker, dispatcher, current_time) 


def test_AttackUmpire():
    class PhonyDispatch:
        def __init__(self, attacker):
            self.attacker = attacker
            self._closed = 0
            self._forwarded = False
        def close(self):
            self._closed += 1
        def forward(self):
            self._forwarded += 1

    ump = AttackUmpire(None, time_limit=10.0)
    
    A1 = PhonyDispatch("alice")
    ump.handle_accepted(A1, 1)
    assert ump._cur and (ump._cur.attacker == A1.attacker)
    assert A1._forwarded == 1
    assert A1._closed == 0
    
    ump.heartbeat(11)
    assert not ump._cur
    assert A1._closed == 1

     
    A1 = PhonyDispatch("alice")
    A2 = PhonyDispatch(A1.attacker)
    ump.handle_accepted(A1, 1)
    ump.handle_accepted(A2, 2)
    assert A1._forwarded == 1
    assert A2._forwarded == 1
    assert ump._cur and (ump._cur.attacker == A1.attacker)

    B1 = PhonyDispatch("bob")
    ump.handle_accepted(B1, 2)
    assert B1._forwarded == 0

    ump.handle_closed(A1, 5)
    assert ump._cur and (ump._cur.attacker == A1.attacker)
    assert A2._closed == 0
    assert B1._forwarded == 0
    ump.handle_closed(A2, 7)
    assert ump._cur and (ump._cur.attacker == B1.attacker)
    assert B1._forwarded == 1
    ump.heartbeat(13)   # From original queueing (NO)
    assert B1._closed == 0
    ump.heartbeat(18)   # From time unleashed (YES)
    assert B1._closed == 1
    assert not ump._cur


BUFFER_SIZE = 4096

class ProxyMate(asyncore.dispatcher_with_send):
    '''The half of a proxy connection that connects to the target.'''
    
    log = logging.getLogger("proxy")
    
    def __init__(self, mate, destination):
        super().__init__()
        self.create_socket()
        self.connect(destination)
        self._mate = mate

    def handle_connect(self):
        self.log.debug("one of [{0}]'s connections has rung through!".format(self._mate.attacker))

    def handle_read(self):
        data = self.recv(BUFFER_SIZE)
        if data:
            self.log.debug("[{0}] <- target ({1} bytes)".format(self._mate.attacker, len(data)))
            self._mate.send(data)
    
    def handle_close(self):
        self.log.info("the target closed one of [{0}]'s connections".format(self._mate.attacker))
        self.close()

        # Safely close our mate (prevent infinite recursion if it tries to close us in return)
        m = self._mate
        if m is not None:
            self._mate = None
            m.handle_close(relay=True)    # So that the Umpire gets notified


class ProxyHandler(asyncore.dispatcher_with_send):
    '''The half of a proxy connection that handles the client connection to the proxy.'''
    
    log = logging.getLogger("proxy")
    
    def __init__(self, server, socket, attacker):
        super().__init__(socket)
        self.attacker = attacker
        self._server = server
        self._mate = None
    
    def close(self):
        super().close()
        
        # Safely close our mate (prevent infinite recursion if it tries to close us in return)
        m = self._mate
        if m is not None:
            self._mate = None
            m.close()

    def readable(self):
        '''No sense reading incoming data until we've been forwarded...'''
        return (self._mate is not None)
    
    def forward(self):
        '''Proxy through to destination on command.'''
        self._mate = ProxyMate(self, self._server.warden.address)

    def handle_read(self):
        data = self.recv(BUFFER_SIZE)
        if data:
            self.log.debug("[{0}] -> target ({1} bytes)".format(self.attacker, len(data)))
            self._mate.send(data)   # We should never read data until we have a _mate, so this should be safe

    def handle_close(self, relay=False):
        if not relay:
            # If relay == True, this is a relayed closure from the server side, not
            # actually the attacker closing it...
            self.log.info("[{0}] closed one its own connections".format(self.attacker))
        self.close()
        self._server.umpire.handle_closed(self)


class ProxyServer(asyncore.dispatcher):
    '''The server listening for client connections to proxy.'''
    
    log = logging.getLogger("proxy")
    
    def __init__(self, listen_addr, warden, umpire):
        """Listen on <listen_addr>; use <warden> to locate forwarding address; notify <umpire> of new connections/closures.
        """
        super().__init__()
        self.warden = warden
        self.umpire = umpire

        self.create_socket()
        self.set_reuse_addr()
        self.bind(listen_addr)
        self.listen(5)

    def handle_accepted(self, sock, addr):
        self.umpire.handle_accepted(ProxyHandler(self, sock, addr[0]))


class Warden:
    '''Launches and stands watch over a webserver process.
    
    Assumes a compliant CpS 320 webserver that accepts the following options:
    
        ./executable_name [OTHER OPTIONS] -h HOSTNAME -p PORT
    
    '''
    
    log = logging.getLogger("warden")
    
    # How long to wait for a local server response
    TIMEOUT = 0.5   # Seconds
    
    def __init__(self, exec_args, logfile_name="webserver.log", listen_host="localhost", listen_port=5000):
        '''Spawn the process so it can be monitored.
        
        execargs: a list of strings suitable for use with subprocess.Popen
                    (will have ['-h', <listen_host>, '-p', <listen_port>] appended to it)
        '''
        self._listen_host = listen_host
        self._listen_port = int(listen_port)    # Make sure we can increment this to avoid "address in use" errors on respawn
        self._logfile_name = logfile_name
        self._exec_args = exec_args
        
        self._proc = None
        self._respawn()
    
    def __del__(self):
        if self._proc:
            self._proc.kill()
    
    @property
    def address(self):
        '''What (host, port) to forward connections to.'''
        return (self._listen_host, self._listen_port)
    
    def _respawn(self):
        ''' Internal helper to actually [re-]launch the webserver.'''
        args = self._exec_args + ['-h', self._listen_host, '-p', str(self._listen_port)]
        try:
            self.log.info("Spawning webserver at port {} (logging to {})".format(self._listen_port, self._logfile_name))
            with open(self._logfile_name, "ab") as logfile:
                self._proc = subprocess.Popen(args,
                                stdin=subprocess.DEVNULL,
                                stdout=logfile,
                                stderr=subprocess.STDOUT)
        except:
            self.log.exception("Error spawning webserver process:")
            self._proc = None
            raise   # Don't try to contain it, just log it on the way out
    
    def _request(self, path, timeout):
        '''Internal helper to request a resource from the server.
        
        Used to qualify contestants and to ping the server for responsiveness.
        Returns response object on success, None on failure (logs all details).
        '''
        try:
            self.log.debug("Hitting ({0}:{1}) with a 'GET {2}' request...".format(self._listen_host, self._listen_port, path))
            conn = http.client.HTTPConnection(self._listen_host, self._listen_port, timeout)
            conn.request("GET", path)
            resp = conn.getresponse()
            self.log.debug("...got {0} ({1}) response!".format(resp.status, resp.reason))
            return resp
        except socket.timeout:
            # So it's not responding...
            self.log.debug("Server did not respond (request timeout)!")
            return None
        except:
            # This is interesting...
            self.log.exception("Error requesting resource:")
            return None
    
    def check(self, get_path="/test.txt", timeout=TIMEOUT) -> tuple:
        '''Check the processes for both liveness and responsiveness.
        
        If the process is dead: respawn, and return (True, dead_status_code).
        If the process is hung (timeout on test request): kill it, respawn it, and return (True, None).
        Otherwise, return (False, None).
        '''
        # Check for hung server
        resp = self._request(get_path, timeout)
        if (not resp) or (resp.status != 200):
            # Whatever happened, we're going to respawn--so bump our local-listen port
            # to avoid stupid "address in use" errors on server startup
            self._listen_port += 1
            
            # Check for process death...
            exit_status = self._proc.poll()
            if exit_status is not None:
                self.log.info("webserver DIED (status={0}); respawning...".format(exit_status))
                self._respawn()
                return (True, exit_status)
            else:
                self.log.info("webserver not responding [properly] (status={0}); bouncing...".format(getattr(resp, "status", None)))
                try:
                    self._proc.kill()
                except:
                    self.log.exception("Error killing webserver process:")
                self._respawn()
                return (True, None)
        
        # All checks passed!
        return (False, None)

class Judge:
    '''Master event coordinator that renders verdicts on who killed whom.
    '''
    log = logging.getLogger("judge")
    
    def __init__(self, warden):
        '''Use <warden> to monitor/bounce server process.
        '''
        self._warden = warden
    
    def notify_attack_ended(self, attacker, timed_out=False):
        '''Informs the judge that an attack (from <attacker>) has ended.
        
        If timed_out is True, it means the attack ended because the umpire
        disrupted the connections.
        '''
        score, status = self._warden.check()
        if score:
            if status is None:
                # Hung server
                self.log.info("Attack from {0} results in HUNG SERVER!".format(attacker))
            else:
                # Crashed server
                self.log.info("BOOM! Attack from {0} KILLED the server! (exit code: {1})".format(attacker, status))
        else:
            self.log.info("Attack from {0} passes without incident...".format(attacker))

            
def can_bind(listen_host: str) -> bool:
    """Can we bind a socket to the given hostname/IP?
    
    If not, we may be NAT'd (and we're definitely not participating in the Wars).
    """
    dummy = socket.socket(socket.AF_INET)
    try:
        dummy.bind((listen_host, 0))
    except OSError:
        return False
    else:
        return True


def main(argv):
    import argparse
    
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", default=False, action="store_true", help="Turn on verbose/debugging log messages.")
    ap.add_argument("-t", "--timeout", type=float, default=5.0, help="Maximum time allotted to each attacker (by source IP) at a time.")
    ap.add_argument("-n", "--listen-host", default="localhost", help="Hostname/interface on which listen.")
    ap.add_argument("-p", "--listen-port", type=int, default=8080, help="Port number on which to listen.")
    ap.add_argument("-N", "--forward-host", default="localhost", help="Hostname/IP to which to forward connections.")
    ap.add_argument("-P", "--forward-port", type=int, default=5001, help="Port number to which to forward connections.")
    ap.add_argument("-o", "--observer-host", default=None, help="Observer server hostname/IP.")
    ap.add_argument("-q", "--observer-port", default=1337, help="Observer server port number.")
    ap.add_argument("execargs", nargs="+", help="Command[s] to launch webserver (without -h/-p options).")
    args = ap.parse_args(argv[1:])
    
    if not can_bind(args.listen_host):
        print("\n*** ERROR: cannot bind to '{0}'--make sure your VM network adapter is set to Bridged!".format(args.listen_host), file=sys.stderr)
        sys.exit(1)
    
    fmt = "%(asctime)s|%(process)d|%(name)s|%(levelname)s|%(message)s"
    lvl = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(format=fmt, level=lvl)
    
    # Only judge messages should go to the observer
    if args.observer_host is not None:
        dgram_logger = logging.handlers.DatagramHandler(args.observer_host, args.observer_port)
        logging.getLogger('judge').addHandler(dgram_logger)
    
    warden = Warden(args.execargs, listen_host=args.forward_host, listen_port=args.forward_port)
    print("\n*** Webserver spawned; testing connectivity...\n")
    for i in range(3):
        time.sleep(i * 5.0 + 1.0) # Warm-up/back-off time
        down, status = warden.check()
        if not down:
            break
    else:
        # All 3 tries resulted in "down"
        print("\n*** ERROR: the webserver was not successfully launched (or isn't properly configured to serve up /test.txt)", file=sys.stderr)
        sys.exit(1)
    
    print("\n*** OK: we're off to the races! Direct your attacks to http://{}:{}\n".format(args.listen_host, args.listen_port))
    judge = Judge(warden)
    umpire = AttackUmpire(judge, time_limit=args.timeout)
    proxy = ProxyServer((args.listen_host, args.listen_port), warden, umpire)
    while True:
        asyncore.loop(0.5, count=1)
        umpire.heartbeat()

if __name__ == "__main__":
    main(sys.argv)
