#!/usr/bin/env python3

# capture_pedestal_events.py: Captures pedestal events from PANOSETI quabo boards by sending software 
#                             trigger commands at a specified frequency and recording their responses 
#                             in PCAPNG and PFF format.

# Author: Stephen Fegan <sfegan@llr.in2p3.fr> (2026-05-30)
# Laboratoire Leprince-Ringuet, CNRS/IN2P3, Ecole Polytechnique, Institut Polytechnique de Paris

# AI usage: Gemini-CLI

import asyncio
import struct
import time
import datetime
import argparse
import socket
import concurrent.futures
import logging
import array
import abc
import signal

class DataWriter(abc.ABC):
    @abc.abstractmethod
    def write_packet(self, q, pixel_data, ts_tai: int,
                     nanosec: int, ts_utc: float, cycle_count: int) -> None: ...

    @abc.abstractmethod
    def close(self) -> None: ...

class ScopeFormatter(logging.Formatter):
    """Custom formatter that ensures 'scope' always exists to avoid KeyErrors."""
    def format(self, record):
        if not hasattr(record, 'scope'):
            record.scope = 'System'
        return super().format(record)

# Root logger setup: remove existing handlers and add our custom one
_root_logger = logging.getLogger()
for _h in _root_logger.handlers[:]:
    _root_logger.removeHandler(_h)

_handler = logging.StreamHandler()
_handler.setFormatter(ScopeFormatter(
    fmt='%(asctime)s [%(scope)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
_root_logger.addHandler(_handler)
_root_logger.setLevel(logging.INFO)
logger = logging.getLogger('capture_pedestals')

MAX_FREQUENCY = 1000   # Hard upper limit (Hz)
MIN_TIMEOUT   = 0.002  # Hard lower limit on auto-computed timeout (seconds)

# Payload size constants for science packet extraction from raw QUABO response
_PKT_HEADER_OFFSET = 4
_PKT_PAYLOAD_LEN    = 512
_PKT_PAYLOAD_END   = _PKT_HEADER_OFFSET + _PKT_PAYLOAD_LEN # 516

# Pre-built trigger command — 64 bytes, first byte 0x0c, rest zero.
# Built once at import time so struct.pack() is never called in the hot path.
_TRIGGER_CMD = struct.pack('B', 0x0c) + b'\x00' * 63

# Site configuration
SITES = {
    'gattini': {
        'base_ip': '192.168.3.248',
        'daq_ip': '192.168.0.4',
        'module_id': 254,
        'scope': 'Gattini'
    },
    'winter': {
        'base_ip': '192.168.3.244',
        'daq_ip': '192.168.0.6',
        'module_id': 253,
        'scope': 'Winter'
    },
    'fern': {
        'base_ip': '192.168.3.240',
        'daq_ip': '192.168.0.9',
        'module_id': 252,
        'scope': 'Fern'
    },
    'pti': {
        'base_ip': '192.168.3.232',
        'daq_ip': '192.168.0.8',
        'module_id': 250,
        'scope': 'PTI'
    },
    'localhost': {
        'base_ip': '127.0.0.1',
        'daq_ip': '127.0.0.1',
        'module_id': 0,
        'scope': 'Emulator',
        'use_ports': True
    },
}

###################################################################################################
#
#    8888888b.   .d8888b.        d8888 8888888b.  
#    888   Y88b d88P  Y88b      d88888 888   Y88b 
#    888    888 888    888     d88P888 888    888 
#    888   d88P 888           d88P 888 888   d88P 
#    8888888P"  888          d88P  888 8888888P"  
#    888        888    888  d88P   888 888        
#    888        Y88b  d88P d8888888888 888        
#    888         "Y8888P" d88P     888 888        
#
###################################################################################################

class PcapngWriter(DataWriter):
    """
    Self-contained Pcapng writer with background I/O, buffering, and rollover.
    """
    # PCAP constants
    _ETH_HDR_LEN    = 14
    _IP_HDR_LEN     = 20
    _UDP_HDR_LEN    = 8
    _SCI_HDR_LEN    = 16
    _PIXEL_DATA_LEN = 512

    # Pcapng structural constants
    _EPB_HDR_LEN    = 28
    _EPB_FTR_LEN    = 4

    # Derived lengths
    _ETH_IP_LEN     = _ETH_HDR_LEN + _IP_HDR_LEN # 34
    _NET_HDR_LEN    = _ETH_IP_LEN + _UDP_HDR_LEN  # 42
    _SCIENCE_LEN    = _SCI_HDR_LEN + _PIXEL_DATA_LEN # 528
    _CAPTURE_LEN    = _NET_HDR_LEN + _SCIENCE_LEN    # 570

    # EPB alignment
    _PAD_LEN        = (4 - (_CAPTURE_LEN % 4)) % 4
    _EPB_PAD        = b'\x00' * _PAD_LEN
    _EPB_TOTAL_LEN  = _EPB_HDR_LEN + _CAPTURE_LEN + _PAD_LEN + _EPB_FTR_LEN

    _EPB_HDR_FORMAT = '<IIIIIII'
    _EPB_FTR_FORMAT = '<I'

    # Science header
    _SCIENCE_HDR_FORMAT = '<BBHHIIH'

    @staticmethod
    def calculate_checksum(data_list):
        """Calculates the 16-bit one's complement sum over a list of buffers."""
        s = 0
        for data in data_list:
            if len(data) % 2 == 1:
                data = bytes(data) + b'\x00'
            # Fast C-level struct unpacking; note: 'H' is endian-dependent but 
            # compensated for by htons() for standard network-order (big-endian) checksums.
            words = array.array('H')
            words.frombytes(data)
            s += sum(words)
        
        while (s >> 16):
            s = (s & 0xFFFF) + (s >> 16)
            
        cksum = ~s & 0xffff
        return socket.htons(cksum)

    @staticmethod
    def calculate_udp_checksum(src_ip, dst_ip, udp_hdr_no_cksum, payload):
        """Calculates the UDP checksum including the pseudo-header."""
        pseudo_hdr = struct.pack('!4s4sBBH',
                                 socket.inet_aton(src_ip),
                                 socket.inet_aton(dst_ip),
                                 0, 17, len(udp_hdr_no_cksum) + len(payload))
        cksum = PcapngWriter.calculate_checksum([pseudo_hdr, udp_hdr_no_cksum, payload])
        # RFC 768: If computed checksum is 0, transmit as 0xffff (all ones)
        return cksum if cksum != 0 else 0xffff

    def __init__(self, template: str, scope: str, site_info: dict,
                 quabos: list, rollover: int, buffer: int,
                 compute_checksums: bool, logger) -> None:
        self.template = template
        self.scope = scope
        self.site_info = site_info
        self.quabos = quabos
        self.rollover = rollover
        self.buffer_max = buffer
        self.compute_checksums = compute_checksums
        self.logger = logger

        # Internal state
        self.last_rollover_mono = 0
        self.packets_written_total = 0
        self.current_filename = None
        self.file_handle = None
        self.packets_in_current_file = 0

        # Buffering
        self.buffer = bytearray(self._EPB_TOTAL_LEN * self.buffer_max)
        self.buffer_ptr = 0
        self.buffer_count = 0

        # Background I/O
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.write_queue = asyncio.Queue()
        self.pending_data_count = 0
        self.disk_misses_since_last_report = 0
        self.writer_task = None
        self.writer_failed = False

        self._precalculate_headers()

    def _precalculate_headers(self):
        """Pre-calculates static Ethernet/IP/UDP headers for each quabo."""
        self.quabo_headers = {}
        for idx, q in enumerate(self.quabos):
            # Ethernet (14B)
            eth = struct.pack('!6s6sH', b'\x00'*6, b'\x00'*6, 0x0800)
            
            # IP (20B)
            total_len = self._IP_HDR_LEN + self._UDP_HDR_LEN + self._SCIENCE_LEN
            ip_no_cksum = struct.pack('!BBHHHBBH4s4s', 
                                      0x45, 0, total_len, 0, 0x4000, 64, 17, 0, 
                                      socket.inet_aton(q.ip), socket.inet_aton(self.site_info['daq_ip']))
            
            ip_cksum = 0
            if self.compute_checksums:
                ip_cksum = self.calculate_checksum([ip_no_cksum])
                
            ip_hdr = struct.pack('!BBHHHBBH4s4s', 
                                 0x45, 0, total_len, 0, 0x4000, 64, 17, ip_cksum, 
                                 socket.inet_aton(q.ip), socket.inet_aton(self.site_info['daq_ip']))
            
            # UDP (8B)
            udp_hdr_base = struct.pack('!HHH', 60001, 60001, self._UDP_HDR_LEN + self._SCIENCE_LEN)
            
            boardloc = (self.site_info['module_id'] << 2) | idx

            if not self.compute_checksums:
                # Full static header possible if no checksums
                udp_hdr = udp_hdr_base + b'\x00\x00'
                precalculated_net_hdr = eth + ip_hdr + udp_hdr
            else:
                # Only Eth + IP is static
                precalculated_net_hdr = eth + ip_hdr
            
            self.quabo_headers[q] = {
                'net_hdr': precalculated_net_hdr,
                'udp_hdr_base': udp_hdr_base,
                'boardloc': boardloc
            }

    def start(self, loop):
        """Starts the background writer task."""
        self.writer_task = loop.create_task(self._disk_writer())

    async def _disk_writer(self):
        """Dedicated coroutine handling ALL disk I/O."""
        loop = asyncio.get_running_loop()
        
        while True:
            item = await self.write_queue.get()
            if item is None: # Shutdown sentinel
                self._close_current_file()
                self.write_queue.task_done()
                self.executor.shutdown(wait=True)
                break
                
            cmd, payload = item
            if cmd == "DATA":
                self.pending_data_count -= 1
            try:
                if cmd == "DATA" and self.file_handle:
                    data, count = payload
                    await loop.run_in_executor(self.executor, self._write_raw, data, count)
                elif cmd == "ROLLOVER":
                    self._close_current_file()
                    # Open the new file safely in the background thread
                    try:
                        await loop.run_in_executor(self.executor, self._open_file, payload)
                    except Exception as e:
                        self.logger.critical(f"[PCAP] Failed to open output file {payload}: {e}. Stopping PCAP writing.")
                        self.writer_failed = True
                        break
            except Exception as e:
                self.logger.error(f"[PCAP] PCAP disk writer error: {e}")
            except BaseException as e:
                self.logger.critical(f"[PCAP] _disk_writer died: {type(e).__name__}: {e}", exc_info=True)
                self.writer_failed = True
                raise
            finally:
                self.write_queue.task_done()

    def _open_file(self, filename):
        self.current_filename = filename
        self.file_handle = open(filename, 'wb')
        self.packets_in_current_file = 0
        self._write_shb()
        self._write_idb()
        self.file_handle.flush()
        self.logger.info(f"[PCAP] Opened {filename}")

    def _close_current_file(self):
        if self.file_handle:
            self.logger.info(f"[PCAP] Closing {self.current_filename}, {self.packets_in_current_file} packets written.")
            self.file_handle.close()
            self.file_handle = None
            self.current_filename = None

    def _write_shb(self):
        # Section Header Block (SHB)
        os_str = "Linux".encode('utf-8')
        os_pad = (4 - (len(os_str) % 4)) % 4
        appl_str = "PANOSETI Pedestal Capture".encode('utf-8')
        appl_pad = (4 - (len(appl_str) % 4)) % 4
        
        # Options: shb_os (3), shb_userappl (4), opt_endofopt (0)
        options = (
            struct.pack('<HH', 3, len(os_str)) + os_str + b'\x00' * os_pad +
            struct.pack('<HH', 4, len(appl_str)) + appl_str + b'\x00' * appl_pad +
            struct.pack('<HH', 0, 0)
        )
        
        shb_body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
        shb_len = 28 + len(options)
        shb_block = struct.pack('<II', 0x0A0D0D0A, shb_len) + shb_body + options + struct.pack('<I', shb_len)
        self.file_handle.write(shb_block)

    def _write_idb(self):
        # Interface Description Block (IDB)
        # LinkType 1 = Ethernet. Value 9 for if_tsresol means 10^-9 (nanoseconds).
        idb_body = struct.pack('<HHI', 1, 0, 65535)
        options = (
            struct.pack('<HHB', 9, 1, 9) + b'\x00' * 3 +
            struct.pack('<HH', 0, 0)
        )
        idb_len = 20 + len(options)
        idb_block = struct.pack('<II', 0x00000001, idb_len) + idb_body + options + struct.pack('<I', idb_len)
        self.file_handle.write(idb_block)

    def _write_raw(self, data, count):
        if self.file_handle:
            self.file_handle.write(data)
            self.file_handle.flush()
            self.packets_in_current_file += count
            self.packets_written_total += count

    def write_packet(self, q, pixel_data, ts_tai, nanosec, ts_utc, cycle_count) -> None:
        if self.writer_failed:
            return

        # Check for rollover
        self._manage_rollover(ts_utc)

        # Assemble EPB
        ptr = self.buffer_ptr
        hdr = self.quabo_headers[q]
        
        # 1. Pcapng EPB Header (32B)
        ts_total_ns = int(ts_utc) * 1_000_000_000 + int(nanosec)
        ts_high = ts_total_ns >> 32
        ts_low = ts_total_ns & 0xFFFFFFFF
        struct.pack_into(self._EPB_HDR_FORMAT, self.buffer, ptr,
                         0x00000006, self._EPB_TOTAL_LEN, 0, ts_high, ts_low, self._CAPTURE_LEN, self._CAPTURE_LEN)
        
        # 2. Network Header (Eth + IP + UDP)
        if not self.compute_checksums:
            # Full static header (42B)
            self.buffer[ptr+self._EPB_HDR_LEN:ptr+self._EPB_HDR_LEN+self._NET_HDR_LEN] = hdr['net_hdr']
            sci_ptr = ptr + self._EPB_HDR_LEN + self._NET_HDR_LEN
        else:
            # Static Eth + IP (34B)
            self.buffer[ptr+self._EPB_HDR_LEN:ptr+self._EPB_HDR_LEN+self._ETH_IP_LEN] = hdr['net_hdr']
            
            # 3. Science Header (16B) - written early for checksumming
            sci_ptr = ptr + self._EPB_HDR_LEN + self._NET_HDR_LEN
            struct.pack_into(self._SCIENCE_HDR_FORMAT, self.buffer, sci_ptr,
                             0x01, 1, cycle_count % 65536, hdr['boardloc'], ts_tai, nanosec, 1)
            
            # 4. Pixel Data (512B) - written early for checksumming
            self.buffer[sci_ptr+self._SCI_HDR_LEN:sci_ptr+self._SCI_HDR_LEN+self._PIXEL_DATA_LEN] = pixel_data
            
            # Calculate UDP checksum using a memoryview of the assembled payload
            payload_view = memoryview(self.buffer)[sci_ptr:sci_ptr+self._SCIENCE_LEN]
            udp_cksum = self.calculate_udp_checksum(q.ip, self.site_info['daq_ip'], hdr['udp_hdr_base'] + b'\x00\x00', payload_view)
            
            # UDP Header (8B)
            self.buffer[ptr+self._EPB_HDR_LEN+self._ETH_IP_LEN:ptr+self._EPB_HDR_LEN+self._ETH_IP_LEN+6] = hdr['udp_hdr_base']
            struct.pack_into('!H', self.buffer, ptr+self._EPB_HDR_LEN+self._ETH_IP_LEN+6, udp_cksum)

        if not self.compute_checksums:
            # 3. Science Header (16B)
            struct.pack_into(self._SCIENCE_HDR_FORMAT, self.buffer, sci_ptr,
                             0x01, 1, cycle_count % 65536, hdr['boardloc'], ts_tai, nanosec, 1)
            
            # 4. Pixel Data (512B)
            self.buffer[sci_ptr+self._SCI_HDR_LEN:sci_ptr+self._SCI_HDR_LEN+self._PIXEL_DATA_LEN] = pixel_data
        
        # 5. EPB Padding and Footer
        self.buffer[ptr+self._EPB_HDR_LEN+self._CAPTURE_LEN:ptr+self._EPB_HDR_LEN+self._CAPTURE_LEN+self._PAD_LEN] = self._EPB_PAD
        struct.pack_into(self._EPB_FTR_FORMAT, self.buffer, ptr+self._EPB_TOTAL_LEN-4, self._EPB_TOTAL_LEN)
        
        self.buffer_ptr += self._EPB_TOTAL_LEN
        self.buffer_count += 1
        
        if self.buffer_count >= self.buffer_max:
            self._flush_buffer_to_queue()

    def _flush_buffer_to_queue(self):
        if self.buffer_count == 0:
            return
            
        data = bytes(self.buffer[:self.buffer_ptr])
        self._enqueue_item(("DATA", (data, self.buffer_count)))
        
        self.buffer_ptr = 0
        self.buffer_count = 0

    def _manage_rollover(self, ts_utc):
        mono = time.monotonic()
        is_due = (self.last_rollover_mono == 0 or 
                  (self.rollover > 0 and mono - self.last_rollover_mono >= self.rollover))

        if is_due:
            self._flush_buffer_to_queue()

            dt = datetime.datetime.fromtimestamp(ts_utc)
            filename = self.template.format(
                scope=self.scope, date=dt.strftime('%Y%m%d'), time=dt.strftime('%H%M%S')
            )
            self._enqueue_item(("ROLLOVER", filename))
            self.last_rollover_mono = mono

    def _enqueue_item(self, item):
        cmd, payload = item
        if cmd == "DATA":
            if self.pending_data_count >= 100:
                _, count = payload
                if self.disk_misses_since_last_report == 0:
                    self.logger.warning(f"[PCAP] PCAP write queue full — dropping {count} packets (further warnings suppressed)")
                self.disk_misses_since_last_report += count
                return
            self.pending_data_count += 1            
        self.write_queue.put_nowait(item)

    def drain_miss_count(self) -> int:
        count = self.disk_misses_since_last_report
        self.disk_misses_since_last_report = 0
        return count

    def close(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            loop_is_running = loop.is_running()
        except (RuntimeError, AttributeError):
            loop_is_running = False
        
        if loop_is_running:
            try:
                self._flush_buffer_to_queue()
                self.write_queue.put_nowait(None)
            except (RuntimeError, asyncio.QueueFull):
                pass
        else:
            if self.buffer_count > 0:
                data = bytes(self.buffer[:self.buffer_ptr])
                self.write_queue.put_nowait(("DATA", (data, self.buffer_count)))
            self.write_queue.put_nowait(None)
            # If the loop is already dead, the _disk_writer task won't run.
            # We must shutdown the executor here to at least try to flush.
            self.executor.shutdown(wait=True)

###################################################################################################
#
#    8888888b.  8888888888 8888888888 
#    888   Y88b 888        888        
#    888    888 888        888        
#    888   d88P 8888888    8888888    
#    8888888P"  888        888        
#    888        888        888        
#    888        888        888        
#    888        888        888        
#
###################################################################################################

class PffWriter(DataWriter):
    def __init__(self, template: str, scope: str, max_size_mb: int, logger) -> None:
        self.template = template
        self.scope = scope
        self.max_size_mb = max_size_mb
        self.logger = logger

    def write_packet(self, q, pixel_data, ts_tai, nanosec, ts_utc, cycle_count) -> None:
        self.logger.debug("PffWriter: write_packet (stub)")

    def close(self) -> None:
        pass

###################################################################################################
#
#     .d88888b.                    888               
#    d88P" "Y88b                   888               
#    888     888                   888               
#    888     888 888  888  8888b.  88888b.   .d88b.  
#    888     888 888  888     "88b 888 "88b d88""88b 
#    888 Y8b 888 888  888 .d888888 888  888 888  888 
#    Y88b.Y8b88P Y88b 888 888  888 888 d88P Y88..88P 
#     "Y888888"   "Y88888 "Y888888 88888P"   "Y88P"  
#           Y8b                                      
#                                                    
###################################################################################################

class QuaboManager(asyncio.DatagramProtocol):
    """Manages a single persistent UDP socket for all quabos."""
    def __init__(self):
        self.transport = None
        self.pending_requests = {}  # (ip, port) -> Future

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        future = self.pending_requests.pop(addr, None)
        if future and not future.done():
            future.set_result(data)

    def send_all(self, quabos):
        """
        Send trigger commands to all quabos in a single synchronous burst.
        Registers a Future for each board and fires all sendto() calls with no
        await between them, minimising the skew between the first and last packet
        on the wire.  Returns the list of futures in quabo order.

        Must be called from the event loop thread (i.e. not from an executor).
        """
        loop = asyncio.get_running_loop()
        futures = []
        for q in quabos:
            addr = (q.ip, q.port)
            # Cancel any stale future for this address
            old = self.pending_requests.pop(addr, None)
            if old and not old.done():
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Overwriting pending request for {addr}")
                old.cancel()
            fut = loop.create_future()
            self.pending_requests[addr] = fut
            futures.append((addr, fut))

        # All futures registered — now blast the packets with no yields between.
        sent_futures = []
        for addr, fut in futures:
            try:
                self.transport.sendto(_TRIGGER_CMD, addr)
                sent_futures.append(fut)
            except OSError:
                self.pending_requests.pop(addr, None)
                if not fut.done():
                    fut.cancel()
                sent_futures.append(None)
        return sent_futures

    @staticmethod
    async def wait_all(futures, timeout):
        """
        Await all futures returned by send_all() with a shared total timeout.
        Returns a list of (data | None) in the same order as the futures.
        None means timeout, cancel, or send error.
        """
        # Create a single list of tasks. None values from send_all are 
        # converted to pre-completed futures that return None.
        loop = asyncio.get_running_loop()
        task_list = []
        for fut in futures:
            if fut is None:
                dummy_fut = loop.create_future()
                dummy_fut.set_result(None)
                task_list.append(dummy_fut)
            else:
                task_list.append(fut)

        # Parallel wait for all responses with one global timeout
        done, pending = await asyncio.wait(
            task_list,
            timeout=timeout
        )

        results = [None] * len(task_list)
        for idx, fut in enumerate(task_list):
            if fut in done:
                try:
                    value = fut.result()
                    if isinstance(value, Exception):
                        results[idx] = None
                    else:
                        results[idx] = value
                except Exception:
                    results[idx] = None
            else:
                # If not in done, it's either in pending or was cancelled/failed earlier
                results[idx] = None

        # Cancel any still-pending futures after the timeout expires
        for fut in pending:
            if not fut.done():
                fut.cancel()

        return results

class QuaboClient:
    """Helper to track state for a single quabo board."""
    def __init__(self, ip, port, quadrant):
        self.ip = ip
        self.port = port
        self.quadrant = quadrant
        self.total_missing = 0
        self.consecutive_misses = 0
        self.is_down = False
        # Stats for per-minute reporting
        self.misses_since_last_report = 0
        # Per-board first-response flag for startup confirmation logging
        self.first_response_logged = False

###################################################################################################
#
#     .d8888b.                                             888                    
#    d88P  Y88b                                            888                    
#    888    888                                            888                    
#    888         .d88b.  88888b.   .d88b.  888d888 8888b.  888888 .d88b.  888d888 
#    888  88888 d8P  Y8b 888 "88b d8P  Y8b 888P"      "88b 888   d88""88b 888P"   
#    888    888 88888888 888  888 88888888 888    .d888888 888   888  888 888     
#    Y88b  d88P Y8b.     888  888 Y8b.     888    888  888 Y88b. Y88..88P 888     
#     "Y8888P88  "Y8888  888  888  "Y8888  888    "Y888888  "Y888 "Y88P"  888     
#
###################################################################################################

class PedestalGenerator:
    def __init__(self, args):
        self.args = args
        self.site_info = SITES[args.site]
        self.scope = self.site_info['scope']
        self.logger = logging.LoggerAdapter(logger, {'scope': self.scope})
        
        self.quabos = self._init_quabos()
        self._validate_quabos()
        
        self.total_generated = 0
        self.generated_since_last_report = 0
        self.dropped_cycles = 0
        
        self.cycle_count = 0
        self.manager = None
        self.transport = None

        self.writers = []
        if args.pcap:
            self.writers.append(PcapngWriter(
                template=args.pcap_output,
                scope=self.scope,
                site_info=self.site_info,
                quabos=self.quabos,
                rollover=args.pcap_rollover,
                buffer=args.pcap_buffer,
                compute_checksums=args.pcap_compute_checksums,
                logger=self.logger
            ))
        if args.pff:
            self.writers.append(PffWriter(
                template=args.pff_output,
                scope=self.scope,
                max_size_mb=args.pff_max_size,
                logger=self.logger
            ))
        
        if not self.writers:
            # This should be caught by argparse validation, but just in case
            raise ValueError("At least one output format must be selected (--pcap and/or --pff)")

        self._watchdog_task = None

        # Calculate effective polling period and trigger offset (phase)
        if self.args.frequency > 0:
            self.period = 1.0 / self.args.frequency
        elif self.args.frequency < 0:
            self.period = float(abs(self.args.frequency))
        else: # 0
            self.period = 1.0
            
        # Per user request: align phase to middle of 1st second (0.5s offset)
        # for low frequencies, or middle of period for high frequencies.
        self.trigger_offset = 0.5 * min(self.period, 1.0)

    def _init_quabos(self):
        """
        Initializes QuaboClient objects. NOTE: Hostname resolution is performed
        synchronously here, which is acceptable during startup before the loop.
        """
        clients = []
        if self.args.quabos:
            for i, q_str in enumerate(self.args.quabos):
                if ':' in q_str:
                    host, port_str = q_str.rsplit(':', 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        host, port = q_str, 60000
                else:
                    host, port = q_str, 60000
                
                # Resolve hostname to IP to ensure QuaboManager matching works
                try:
                    resolved_ip = socket.gethostbyname(host)
                    self.logger.info(f"Resolved {host} to {resolved_ip}")
                except socket.gaierror:
                    self.logger.error(f"Could not resolve hostname: {host}")
                    resolved_ip = host
                
                clients.append(QuaboClient(resolved_ip, port, i))
        else:
            base_ip = self.site_info['base_ip']
            for i in range(4):
                if self.site_info.get('use_ports'):
                    ip, port = base_ip, 60000 + i
                else:
                    ip_parts = base_ip.split('.')
                    ip_parts[-1] = str(int(ip_parts[-1]) + i)
                    ip, port = '.'.join(ip_parts), 60000
                clients.append(QuaboClient(ip, port, i))
        return clients

    def _validate_quabos(self):
        """Ensures all quabos have unique (IP, Port) pairs."""
        addrs = set()
        for q in self.quabos:
            addr = (q.ip, q.port)
            if addr in addrs:
                raise ValueError(f"Duplicate quabo address identified: {addr}")
            addrs.add(addr)

    def _print_watchdog_report(self, is_final=False):
        # Gather disk misses from all writers
        disk_misses = 0
        for writer in self.writers:
            if isinstance(writer, PcapngWriter):
                disk_misses += writer.drain_miss_count()

        if is_final:
            total_activity = self.generated_since_last_report + self.dropped_cycles + sum(q.misses_since_last_report for q in self.quabos) + disk_misses
            if total_activity == 0:
                return
            
        miss_reports = []
        for i, q in enumerate(self.quabos):
            if q.misses_since_last_report > 0:
                miss_reports.append(f"Q{i}: {q.misses_since_last_report}")
        
        # Add disk drops to miss reports
        if disk_misses > 0:
            miss_reports.append(f"Disk: {disk_misses}")
        
        if not miss_reports:
            miss_str = "no missed packets"
        else:
            miss_str = f"missing packets - {', '.join(miss_reports)}"
        
        dropped_str = f", {self.dropped_cycles} cycles dropped" if self.dropped_cycles > 0 else ""
        prefix = "Final" if is_final else f"Last {self.args.watchdog_period}s"
        stats_msg = f"{prefix}: {self.generated_since_last_report} pedestal events generated{dropped_str}, {miss_str}"
        self.logger.info(stats_msg)
        
        # Reset delta stats
        self.generated_since_last_report = 0
        self.dropped_cycles = 0
        for q in self.quabos:
            q.misses_since_last_report = 0

    async def _watchdog(self):
        while True:
            await asyncio.sleep(self.args.watchdog_period)
            self._print_watchdog_report(is_final=False)

    async def run(self):
        loop = asyncio.get_running_loop()
        # Initialize the single shared socket
        self.transport, self.manager = await loop.create_datagram_endpoint(
            lambda: QuaboManager(),
            local_addr=('0.0.0.0', self.args.bind_port)
        )
        
        # Increase OS UDP receive buffer to handle high-frequency bursts
        sock = self.transport.get_extra_info('socket')
        if sock:
            try:
                # Attempt to set receive buffer to 2MB (OS may cap this)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
                actual_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                self.logger.info(f"UDP receive buffer set to {actual_buf} bytes")
            except Exception as e:
                self.logger.warning(f"Could not set UDP receive buffer: {e}")

        local_addr = self.transport.get_extra_info('sockname')
        frequency_string = f'1/{-self.args.frequency}' if self.args.frequency < -1 else f'{max(1,self.args.frequency)}'
        self.logger.info(f"Starting pedestal capture at {frequency_string} Hz")
        self.logger.info(f"Bound to local UDP port {local_addr[1]}")
        
        # Start background tasks with proper handles for clean shutdown
        for writer in self.writers:
            if hasattr(writer, 'start'):
                writer.start(loop)
                if hasattr(writer, 'writer_task') and writer.writer_task:
                    def _on_writer_done(task):
                        if not task.cancelled() and task.exception() is not None:
                            logger.critical(f"Writer task died with exception: {task.exception()}")
                    writer.writer_task.add_done_callback(_on_writer_done)
        
        self._watchdog_task = loop.create_task(self._watchdog())

        # ----------------------------------------------------------------
        # Schedule anchor: record wall time and monotonic time together so
        # that sleep arithmetic uses monotonic (immune to NTP steps) while
        # UTC timestamps are still derived from wall time.
        # ----------------------------------------------------------------
        wall_epoch  = int(time.time())
        mono_anchor = time.monotonic()

        # Skip any slots that have already passed
        now_wall = time.time()
        slot = 0
        while wall_epoch + slot * self.period + self.trigger_offset <= now_wall:
            slot += 1

        # Monotonic time corresponding to the start of wall_epoch
        mono_epoch = mono_anchor - (now_wall - wall_epoch)

        # Per-cycle timeout — auto-computed with a floor to avoid sub-ms values
        # at high frequencies; can be overridden with --timeout.
        if self.args.timeout is not None:
            timeout = self.args.timeout
        else:
            timeout = max(MIN_TIMEOUT, 0.5 * min(self.period, 1.0))

        try:
            while True:
                # Check if any writer task has encountered a critical failure
                writer_failed = False
                for writer in self.writers:
                    if getattr(writer, 'writer_failed', False):
                        self.logger.info(f"A writer failed — stopping capture.")
                        writer_failed = True
                        break
                if writer_failed:
                    break
                
                trigger_wall = wall_epoch + slot * self.period + self.trigger_offset
                trigger_mono = mono_epoch + slot * self.period + self.trigger_offset

                sleep_dur = trigger_mono - time.monotonic()
                while sleep_dur < -0.1:
                    if self.dropped_cycles == 0:
                        self.logger.warning(f"Cycle {slot} is late by {-sleep_dur:.4f}s .. dropping to catch up (further warnings suppressed)")
                    self.dropped_cycles += 1
                    slot += 1
                    self.cycle_count += 1                    
                    trigger_wall += self.period
                    trigger_mono += self.period
                    sleep_dur += self.period
                if sleep_dur > 0:
                    await asyncio.sleep(sleep_dur)

                # ---- Packets on the wire as fast as possible after wake ----
                # send_all() is synchronous: all sendto() calls happen with no
                # await between them, so inter-board skew is only syscall time.
                futures = self.manager.send_all(self.quabos)

                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Starting cycle {slot}, target trigger time: {trigger_wall:.3f}")

                ts_utc = trigger_wall
                ts_tai = int(ts_utc) + self.args.tai_offset
                # Calculate nanoseconds within the current wall-clock second
                nanosec = int(round((trigger_wall % 1.0) * 1_000_000_000))

                # Now await responses — timeout is shared across all boards.
                results = await self.manager.wait_all(futures, timeout)

                # Post-receive housekeeping (rollover, stats, buffering) — all
                # of this happens after packets are already on the wire.
                self.total_generated += 1
                self.generated_since_last_report += 1

                for idx, data in enumerate(results):
                    q = self.quabos[idx]

                    if data and len(data) >= 516:
                        if self.logger.isEnabledFor(logging.DEBUG):
                            self.logger.debug(f"Quabo {idx} responded ({len(data)} bytes)")

                        if not q.first_response_logged:
                            self.logger.info(f"Quabo {idx} at {q.ip} is responding.")
                            q.first_response_logged = True

                        if q.is_down:
                            self.logger.info(f"Quabo {idx} at {q.ip} has recovered.")
                            q.is_down = False
                        q.consecutive_misses = 0

                        # Optimized in-place buffer assembly using memoryview to avoid copies
                        view = memoryview(data)[_PKT_HEADER_OFFSET:_PKT_PAYLOAD_END]
                        for writer in self.writers:
                            writer.write_packet(q, view, ts_tai, nanosec, ts_utc, self.cycle_count)
                    else:
                        if self.logger.isEnabledFor(logging.DEBUG):
                            self.logger.debug(f"Quabo {idx} timeout waiting for response")
                        q.total_missing += 1
                        q.misses_since_last_report += 1
                        q.consecutive_misses += 1
                        if q.consecutive_misses >= 5 and not q.is_down:
                            self.logger.warning(
                                     f"Quabo {idx} at {q.ip} is not responding "
                                     f"(5 consecutive misses). It might be down.")
                            q.is_down = True

                self.cycle_count += 1
                slot += 1
        finally:
            # ----------------------------------------------------------------
            # Clean shutdown: flush remaining data, drain the queue, then close.
            # ----------------------------------------------------------------
            self._print_watchdog_report(is_final=True)
            
            try:
                try:
                    loop = asyncio.get_running_loop()
                    loop_is_running = loop.is_running()
                except (RuntimeError, AttributeError):
                    # Loop is not running (or we're not in an async context)
                    loop_is_running = False
                
                # Close all writers (synchronous cleanup/drain)
                for writer in self.writers:
                    writer.close()
                
                if loop_is_running:
                    # Wait for writer tasks to finish if possible
                    tasks = [w.writer_task for w in self.writers if isinstance(w, PcapngWriter) and w.writer_task]
                    if tasks:
                        try:
                            # In this 'finally' block, we are usually still in the coroutine.
                            await asyncio.wait_for(asyncio.gather(*tasks), timeout=5.0)
                        except (asyncio.TimeoutError, RuntimeError, asyncio.CancelledError):
                            pass
                    
                    # Clean up the watchdog task
                    if self._watchdog_task:
                        self._watchdog_task.cancel()
                        try:
                            await self._watchdog_task
                        except (asyncio.CancelledError, RuntimeError):
                            pass
                else:
                    # Emergency Fallback: The loop is already dead/closing.
                    self.logger.warning("Event loop is not running during shutdown.")
                    if self._watchdog_task:
                        self._watchdog_task.cancel()

                if self.transport:
                    self.transport.close()
            finally:
                pass

async def main():
    parser = argparse.ArgumentParser(description='PANOSETI Pedestal Capture')
    parser.add_argument('--site', '-s', required=True, choices=SITES.keys(), help='Telescope site')
    parser.add_argument('--frequency', '-f', type=int, default=1, help=f'Polling frequency in Hz (1–{MAX_FREQUENCY}, or negative for 1/n Hz)')
    
    # PCAP options
    parser.add_argument('--pcap', action='store_true', help='Enable PCAP output (pcapng format)')
    parser.add_argument('--pcap-output', '-o', default='pedestals_{scope}_{date}_{time}.pcapng', help='Filename template for PCAP files')
    parser.add_argument('--pcap-rollover', type=int, default=600, help='PCAP file rollover interval in seconds')
    parser.add_argument('--pcap-buffer', type=int, default=None, help='Number of packets to buffer before writing to disk. Default: frequency (clamped 60–1000)')
    parser.add_argument('--pcap-compute-checksums', action='store_true', help='Compute IP/UDP checksums in PCAP output (CPU intensive)')
    
    # PFF options
    parser.add_argument('--pff', action='store_true', help='Enable PFF output')
    parser.add_argument('--pff-output', default='pedestals_{scope}_{date}_{time}.pff', help='Filename template for PFF files')
    parser.add_argument('--pff-max-size', type=int, default=1024, help='PFF file size rollover threshold in MB')

    parser.add_argument('--tai-offset', type=int, default=37, help='TAI offset from UTC')
    parser.add_argument('--bind-port', type=int, default=0, help='Local UDP port to bind to (0 for random)')
    parser.add_argument('--log-level', default='INFO', help='Logging level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--timeout', type=float, default=None, help=f'UDP response timeout in seconds (default: max({MIN_TIMEOUT}, 0.5/min(period, 1.0)))')
    parser.add_argument('--quabos', nargs='+', help='List of quabo addresses in host[:port] format. Overrides site defaults.')
    parser.add_argument('--watchdog-period', type=int, default=60, help='Watchdog summary logging period in seconds')
    args = parser.parse_args()

    # ---- Argument validation ----
    if not args.pcap and not args.pff:
        args.pcap = True

    if not (-MAX_FREQUENCY <= args.frequency <= MAX_FREQUENCY):
        parser.error(f'--frequency must be between -{MAX_FREQUENCY} and {MAX_FREQUENCY}')
    
    # Dynamic buffer sizing for PCAP
    if args.pcap:
        if args.pcap_buffer is None:
            if args.frequency > 0:
                args.pcap_buffer = max(60, min(1000, args.frequency))
            else:
                # For low/fractional frequencies, use a sensible floor
                args.pcap_buffer = 60
        if args.pcap_buffer < 1:
            parser.error('--pcap-buffer must be >= 1')
        if args.pcap_rollover < 0:
            parser.error('--pcap-rollover must be >= 0')

    if args.pff:
        if args.pff_max_size <= 0:
            parser.error('--pff-max-size must be > 0')

    if args.timeout is not None and args.timeout <= 0:
        parser.error('--timeout must be > 0')
    if args.watchdog_period <= 0:
        parser.error('--watchdog-period must be > 0')

    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        parser.error(f'Invalid log level: {args.log_level}')
    logging.getLogger().setLevel(numeric_level)

    generator = PedestalGenerator(args)
    await generator.run()

if __name__ == "__main__":
    def _sigterm_handler(signum, frame):
        logger.warning("Received SIGTERM — shutting down")
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, _sigterm_handler)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down pedestal capture...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
