#!/usr/bin/env python3
import asyncio
import struct
import time
import datetime
import argparse
import os
import socket
import concurrent.futures
import logging

# Configure logging
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
    fmt='%(asctime)s [%(levelname)s] [%(scope)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))
_root_logger.addHandler(_handler)
_root_logger.setLevel(logging.INFO)
logger = logging.getLogger('capture_pedestals')

MAX_FREQUENCY = 1000   # Hard upper limit (Hz)
MIN_TIMEOUT   = 0.002  # Hard lower limit on auto-computed timeout (seconds)

# Constants for Zero-Join Buffer (Pcapng EPB + Ethernet + IP + UDP + Science + Payload)
# Ethernet(14) + IP(20) + UDP(8) + Science(16) + Payload(512) = 570 bytes.
# EPB alignment: 570 % 4 = 2 bytes padding.
# Total EPB block: 32 (HDR) + 570 (DATA) + 2 (PAD) + 4 (FTR) = 608 bytes.
_EPB_TOTAL_LEN  = 608
_CAPTURE_LEN    = 570
_SCIENCE_LEN    = 528 # 16 + 512
_EPB_HDR_FORMAT = '<IIIIIII'
_EPB_FTR_FORMAT = '<I'
_SCIENCE_HDR_FORMAT = '<BBHHIIH'

# Pre-built trigger command — 64 bytes, first byte 0x0c, rest zero.
# Built once at import time so struct.pack() is never called in the hot path.
_TRIGGER_CMD = struct.pack('B', 0x0c) + b'\x00' * 63

# Payload size constants for science packet extraction
_PKT_HEADER_OFFSET = 4    # bytes to skip at start of raw quabo response
_PKT_PAYLOAD_END   = 516  # end of the 512-byte pixel payload

def calculate_checksum(data_list):
    """Calculates the 16-bit one's complement sum over a list of buffers."""
    s = 0
    for data in data_list:
        if len(data) % 2 == 1:
            data += b'\x00'
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i+1])
            s += w
    
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xffff

def calculate_udp_checksum(src_ip, dst_ip, udp_hdr_no_cksum, payload):
    """Calculates the UDP checksum including the pseudo-header."""
    pseudo_hdr = struct.pack('!4s4sBBH',
                             socket.inet_aton(src_ip),
                             socket.inet_aton(dst_ip),
                             0, 17, len(udp_hdr_no_cksum) + len(payload))
    return calculate_checksum([pseudo_hdr, udp_hdr_no_cksum, payload])

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

class PcapngWriter:
    """Minimal Pcapng writer with support for SHB, IDB, and EPB with nanosecond precision."""
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'wb')
        self.packets_written = 0
        self._write_shb()
        self._write_idb()
        self.file.flush()

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
        self.file.write(shb_block)

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
        self.file.write(idb_block)

    def write_raw(self, data, count):
        """Writes a pre-assembled block of EPB packets directly to disk."""
        if self.file:
            self.file.write(data)
            self.file.flush()
            self.packets_written += count

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

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
        loop    = asyncio.get_running_loop()
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
        Await all futures returned by send_all() with a shared timeout.
        Returns a list of (data | None) in the same order as the futures.
        None means timeout or send error.
        """
        results = []
        for fut in futures:
            if fut is None:
                results.append(None)
                continue
            try:
                data = await asyncio.wait_for(fut, timeout=timeout)
                results.append(data)
            except asyncio.TimeoutError:
                results.append(None)
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

class PedestalGenerator:
    def __init__(self, args):
        self.args = args
        self.site_info = SITES[args.site]
        self.scope = self.site_info['scope']
        self.logger = logging.LoggerAdapter(logger, {'scope': self.scope})
        
        self.quabos = self._init_quabos()
        self._validate_quabos()
        self._precalculate_headers()
        
        self.total_generated = 0
        self.generated_since_last_report = 0
        self.dropped_cycles = 0
        
        self.cycle_count = 0
        self.last_rollover_sec = 0
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.manager = None
        self.transport = None

        # Pre-allocated zero-join buffer
        self.buffer_ptr = 0
        self.buffer_count = 0
        self.buffer_max = args.buffer
        self.buffer = bytearray(_EPB_TOTAL_LEN * self.buffer_max)

        # Producer-consumer write queue. Bounded to avoid runaway memory if
        # the writer thread falls behind.
        self._write_queue = asyncio.Queue(maxsize=100)
        self._writer_task = None
        self._watchdog_task = None

    def _precalculate_headers(self):
        """Pre-calculates static Ethernet/IP/UDP headers for each quabo."""
        for idx, q in enumerate(self.quabos):
            # Ethernet (14B)
            eth = struct.pack('!6s6sH', b'\x00'*6, b'\x00'*6, 0x0800)
            
            # IP (20B)
            total_len = 20 + 8 + _SCIENCE_LEN
            ip_no_cksum = struct.pack('!BBHHHBBH4s4s', 
                                      0x45, 0, total_len, 0, 0x4000, 64, 17, 0, 
                                      socket.inet_aton(q.ip), socket.inet_aton(self.site_info['daq_ip']))
            
            ip_cksum = 0
            if self.args.checksums:
                ip_cksum = calculate_checksum([ip_no_cksum])
                
            ip_hdr = struct.pack('!BBHHHBBH4s4s', 
                                 0x45, 0, total_len, 0, 0x4000, 64, 17, ip_cksum, 
                                 socket.inet_aton(q.ip), socket.inet_aton(self.site_info['daq_ip']))
            
            # UDP (8B)
            # If checksums are enabled, we can't pre-calculate the full UDP header because 
            # the checksum depends on the payload (which contains variable timestamps).
            # We'll pre-pack the first 6 bytes and handle the checksum in the hot path.
            q.udp_hdr_base = struct.pack('!HHH', 60001, 60001, 8 + _SCIENCE_LEN)
            
            if not self.args.checksums:
                # Full static header possible if no checksums
                udp_hdr = q.udp_hdr_base + b'\x00\x00'
                q.precalculated_net_hdr = eth + ip_hdr + udp_hdr
            else:
                # Only Eth + IP is static
                q.precalculated_net_hdr = eth + ip_hdr
            
            q.boardloc = (self.site_info['module_id'] << 2) | idx

    def _init_quabos(self):
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

    async def _disk_writer(self):
        """Dedicated coroutine handling ALL disk I/O."""
        loop = asyncio.get_running_loop()
        current_writer = None
        
        while True:
            item = await self._write_queue.get()
            if item is None: # Shutdown sentinel
                if current_writer:
                    self.logger.info(f"Closing {current_writer.filename}, {current_writer.packets_written} packets written.")
                    await loop.run_in_executor(self.executor, current_writer.close)
                self._write_queue.task_done()
                break
                
            cmd, payload = item
            try:
                if cmd == "DATA" and current_writer:
                    data, count = payload
                    await loop.run_in_executor(self.executor, current_writer.write_raw, data, count)
                elif cmd == "ROLLOVER":
                    if current_writer:
                        self.logger.info(f"Closing {current_writer.filename}, {current_writer.packets_written} packets written.")
                        await loop.run_in_executor(self.executor, current_writer.close)
                        current_writer = None
                    # Open the new file safely in the background thread
                    current_writer = await loop.run_in_executor(self.executor, PcapngWriter, payload)
                    self.logger.info(f"Opened {current_writer.filename}")
            except Exception as e:
                self.logger.error(f"Disk writer error: {e}")
            finally:
                self._write_queue.task_done()

    def _enqueue_item(self, item):
        """Non-blocking enqueue for commands and data."""
        try:
            self._write_queue.put_nowait(item)
        except asyncio.QueueFull:
            self.logger.warning("Write queue full — dropping oldest item to protect timing")
            try:
                self._write_queue.get_nowait()
                self._write_queue.task_done()
            except asyncio.QueueEmpty:
                pass
            try:
                self._write_queue.put_nowait(item)
            except asyncio.QueueFull:
                self.logger.error("Write queue still full after drop — item lost")

    def _write_pcap(self, q_idx, pixel_data, ts_tai, nanosec, ts_utc):
        """
        Assembles a full Pcapng EPB (including Network and Science headers)
        directly into the pre-allocated bytearray using struct.pack_into.
        """
        q = self.quabos[q_idx]
        ptr = self.buffer_ptr
        
        # 1. Pcapng EPB Header (32B)
        ts_total_ns = int(ts_utc) * 1_000_000_000 + int(nanosec)
        ts_high = ts_total_ns >> 32
        ts_low = ts_total_ns & 0xFFFFFFFF
        struct.pack_into(_EPB_HDR_FORMAT, self.buffer, ptr,
                         0x00000006, _EPB_TOTAL_LEN, 0, ts_high, ts_low, _CAPTURE_LEN, _CAPTURE_LEN)
        
        # 2. Network Header (Eth + IP + UDP)
        if not self.args.checksums:
            # Full static header (42B)
            self.buffer[ptr+32:ptr+74] = q.precalculated_net_hdr
            sci_ptr = ptr + 74
        else:
            # Static Eth + IP (34B)
            self.buffer[ptr+32:ptr+66] = q.precalculated_net_hdr
            
            # Assembly science payload to calculate UDP checksum
            sci_hdr = struct.pack(_SCIENCE_HDR_FORMAT, 0x01, 1, self.cycle_count % 65536, q.boardloc, ts_tai, nanosec, 1)
            payload = sci_hdr + pixel_data
            
            udp_cksum = calculate_udp_checksum(q.ip, self.site_info['daq_ip'], q.udp_hdr_base + b'\x00\x00', payload)
            
            # UDP Header (8B)
            self.buffer[ptr+66:ptr+72] = q.udp_hdr_base
            struct.pack_into('!H', self.buffer, ptr+72, udp_cksum)
            sci_ptr = ptr + 74

        # 3. Science Header (16B)
        struct.pack_into(_SCIENCE_HDR_FORMAT, self.buffer, sci_ptr,
                         0x01, 1, self.cycle_count % 65536, q.boardloc, ts_tai, nanosec, 1)
        
        # 4. Pixel Data (512B)
        self.buffer[sci_ptr+16:sci_ptr+528] = pixel_data
        
        # 5. EPB Padding (2B) and Footer (4B)
        self.buffer[ptr+602:ptr+604] = b'\x00\x00'
        struct.pack_into(_EPB_FTR_FORMAT, self.buffer, ptr+604, _EPB_TOTAL_LEN)
        
        self.buffer_ptr += _EPB_TOTAL_LEN
        self.buffer_count += 1
        
        if self.buffer_count >= self.buffer_max:
            self._flush_buffer_to_queue()

    def _flush_buffer_to_queue(self):
        """Send the current buffer slice to the write queue and reset pointers."""
        if self.buffer_count == 0:
            return
            
        # Create a single copy of the active buffer slice.
        # This is one allocation per 'buffer_max' packets.
        data = bytes(self.buffer[:self.buffer_ptr])
        self._enqueue_item(("DATA", (data, self.buffer_count)))
        
        self.buffer_ptr = 0
        self.buffer_count = 0

    async def _manage_rollover(self, ts_utc):
        """Signals the background thread to roll over the file."""
        if self.last_rollover_sec == 0 or ts_utc - self.last_rollover_sec >= self.args.rollover:
            self._flush_buffer_to_queue()
            
            dt = datetime.datetime.fromtimestamp(ts_utc)
            filename = self.args.output.format(
                scope=self.scope, date=dt.strftime('%Y%m%d'), time=dt.strftime('%H%M%S')
            )
            self.logger.info(f"Requesting file rollover to {filename}")
            
            # Send a "ROLLOVER" command
            self._enqueue_item(("ROLLOVER", filename))
            self.last_rollover_sec = ts_utc

    async def _watchdog(self):
        while True:
            await asyncio.sleep(60) # 1 minute
            
            miss_reports = []
            for i, q in enumerate(self.quabos):
                if q.misses_since_last_report > 0:
                    miss_reports.append(f"Q{i}: {q.misses_since_last_report}")
            
            if not miss_reports:
                miss_str = "no missed packets"
            else:
                miss_str = f"missing packets - {', '.join(miss_reports)}"
            
            dropped_str = f", {self.dropped_cycles} cycles dropped" if self.dropped_cycles > 0 else ""
            stats_msg = f"Last 60s: {self.generated_since_last_report} pedestal events generated{dropped_str}, {miss_str}"
            self.logger.info(stats_msg)
            
            # Reset delta stats
            self.generated_since_last_report = 0
            self.dropped_cycles = 0
            for q in self.quabos:
                q.misses_since_last_report = 0

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
        self.logger.info(f"Starting pedestal capture at {self.args.frequency} Hz")
        self.logger.info(f"Bound to local UDP port {local_addr[1]} (buffer={self.args.buffer})")
        
        # Start background tasks with proper handles for clean shutdown
        self._writer_task   = asyncio.create_task(self._disk_writer())
        self._watchdog_task = asyncio.create_task(self._watchdog())

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
        while wall_epoch + (slot + 0.5) / self.args.frequency <= now_wall:
            slot += 1

        # Monotonic time corresponding to the start of wall_epoch
        mono_epoch = mono_anchor - (now_wall - wall_epoch)

        # Per-cycle timeout — auto-computed with a floor to avoid sub-ms values
        # at high frequencies; can be overridden with --timeout.
        if self.args.timeout is not None:
            timeout = self.args.timeout
        else:
            timeout = max(MIN_TIMEOUT, 0.5 / self.args.frequency)

        # Create the initial pcap file immediately
        await self._manage_rollover(wall_epoch)
        
        period = 1 / self.args.frequency
        try:
            while True:
                trigger_wall = wall_epoch + (slot + 0.5) / self.args.frequency
                trigger_mono = mono_epoch + (slot + 0.5) * period

                sleep_dur = trigger_mono - time.monotonic()
                while sleep_dur < -0.1: #* self.args.frequency < -0.2:
                    if self.dropped_cycles == 0:
                        self.logger.warning(f"Cycle {slot} is late by {-sleep_dur:.4f}s .. dropping to catch up (further warnings suppressed until next report)")
                    self.dropped_cycles += 1
                    slot += 1
                    self.cycle_count += 1                    
                    trigger_wall += period
                    trigger_mono += period
                    sleep_dur += 1 / self.args.frequency
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
                slot_within_second = slot % self.args.frequency
                nanosec = int((slot_within_second + 0.5) * period * 1_000_000_000)

                # Now await responses — timeout is shared across all boards.
                results = await self.manager.wait_all(futures, timeout)

                # Post-receive housekeeping (rollover, stats, buffering) — all
                # of this happens after packets are already on the wire.
                await self._manage_rollover(int(ts_utc))
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

                        # Optimized in-place buffer assembly
                        self._write_pcap(idx, data[_PKT_HEADER_OFFSET:_PKT_PAYLOAD_END], ts_tai, nanosec, ts_utc)
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
            self._flush_buffer_to_queue()

            # Shutdown sentinel — _disk_writer exits after processing this
            await self._write_queue.put(None)
            try:
                await asyncio.wait_for(self._writer_task, timeout=10.0)
            except asyncio.TimeoutError:
                self.logger.error("Writer task did not finish in time — some data may be lost")
                self._writer_task.cancel()

            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass

            if self.transport:
                self.transport.close()
            self.executor.shutdown(wait=False)

async def main():
    parser = argparse.ArgumentParser(description='PANOSETI Pedestal Capture')
    parser.add_argument('--site', '-s', required=True, choices=SITES.keys(), help='Telescope site')
    parser.add_argument('--frequency', type=int, default=1, help=f'Polling frequency in Hz (1–{MAX_FREQUENCY})')
    parser.add_argument('--rollover', type=int, default=600, help='File rollover interval in seconds')
    parser.add_argument('--output', '-o', default='pedestals_{scope}_{date}_{time}.pcapng', help='Output filename template')
    parser.add_argument('--tai-offset', type=int, default=37, help='TAI offset from UTC')
    parser.add_argument('--bind-port', type=int, default=0, help='Local UDP port to bind to (0 for random)')
    parser.add_argument('--buffer', type=int, default=None, help='Number of packets to buffer before writing to disk. Default: frequency (clamped 60–1000)')
    parser.add_argument('--checksums', action='store_true', help='Enable IP and UDP checksum calculation (CPU intensive)')
    parser.add_argument('--log-level', default='INFO', help='Logging level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--timeout', type=float, default=None, help=f'UDP response timeout in seconds (default: max({MIN_TIMEOUT}, 0.5/frequency))')
    parser.add_argument('--quabos', nargs='+', help='List of quabo addresses in host[:port] format. Overrides site defaults.')
    args = parser.parse_args()

    # ---- Argument validation ----
    if not (1 <= args.frequency <= MAX_FREQUENCY):
        parser.error(f'--frequency must be between 1 and {MAX_FREQUENCY}')
    
    # Dynamic buffer sizing
    if args.buffer is None:
        args.buffer = max(60, min(1000, args.frequency))

    if args.buffer < 1:
        parser.error('--buffer must be >= 1')
    if args.rollover < 1:
        parser.error('--rollover must be >= 1')
    if args.timeout is not None and args.timeout <= 0:
        parser.error('--timeout must be > 0')

    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {args.log_level}')
    logging.getLogger().setLevel(numeric_level)

    generator = PedestalGenerator(args)
    await generator.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down pedestal capture...")
