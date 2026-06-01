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
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('capture_pedestals')

MAX_FREQUENCY = 1000   # Hard upper limit (Hz)
MIN_TIMEOUT   = 0.002  # Hard lower limit on auto-computed timeout (seconds)

def calculate_ip_checksum(header):
    """Calculates the 16-bit one's complement sum of the IPv4 header."""
    if len(header) % 2 == 1:
        header += b'\x00'
    
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + (header[i+1])
        s += w
    
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def repack_science_packet(pixel_data, packet_no, boardloc, tai_seconds, nanoseconds):
    """
    Repacks 256 pixel values into a 528-byte PANOSETI science packet.
    
    Header Layout (16 bytes):
    - Offset 0 (1B): acq_mode (0x01 = Pulse Height)
    - Offset 1 (1B): packet_ver (1 = 16-bit signed PH)
    - Offset 2 (2B): packet_no (16-bit sequence number, Little-Endian)
    - Offset 4 (2B): boardloc (16-bit location ID: bits 15:8=Aperture, 1:0=Quadrant)
    - Offset 6 (4B): TAI (32-bit seconds since epoch)
    - Offset 10 (4B): NANOSEC (32-bit nanoseconds since last tick)
    - Offset 14 (2B): flags (Bit 0 = SW-triggered event)
    """
    header = struct.pack('<BBHHIIH', 
                         0x01, 1, packet_no, boardloc, 
                         tai_seconds, nanoseconds, 1)
    return header + pixel_data

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

    def write_batch(self, packet_batch):
        """
        Writes a batch of packets to disk in a single operation.
        Each element in packet_batch is (data, ts_seconds, ts_nanoseconds).
        """
        blocks = []
        for data, ts_seconds, ts_nanoseconds in packet_batch:
            # Pcapng with if_tsresol=9 uses ticks of 10^-9.
            ts_total_ns = int(ts_seconds) * 1_000_000_000 + int(ts_nanoseconds)
            ts_high = ts_total_ns >> 32
            ts_low = ts_total_ns & 0xFFFFFFFF
            
            cap_len = len(data)
            padding_len = (4 - (cap_len % 4)) % 4
            
            # Type(4) + TotalLen(4) + InterfaceID(4) + TSHigh(4) + TSLow(4) + CapLen(4) + OrigLen(4) + Data + Padding + TotalLen(4)
            # = 32 + data + padding
            epb_len = 32 + cap_len + padding_len
            
            blocks.append(struct.pack('<IIIIIII', 0x00000006, epb_len, 0, ts_high, ts_low, cap_len, cap_len))
            blocks.append(data)
            blocks.append(b'\x00' * padding_len)
            blocks.append(struct.pack('<I', epb_len))
        
        if blocks:
            self.file.write(b''.join(blocks))
            self.file.flush()
            self.packets_written += len(packet_batch)

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

def create_ethernet_ip_udp_packet(payload, src_ip, dst_ip, src_port, dst_port):
    """Wraps payload in Ethernet, IPv4 (with checksum), and UDP headers."""
    # Ethernet Header (14 bytes)
    eth_hdr = struct.pack('!6s6sH', b'\x00'*6, b'\x00'*6, 0x0800)
    
    # IPv4 Header (20 bytes)
    total_len = 20 + 8 + len(payload)
    # Pack header with 0 checksum first
    ip_hdr_no_cksum = struct.pack('!BBHHHBBH4s4s', 
                                  0x45, 0, total_len, 0, 0x4000, 64, 17, 0, 
                                  socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    cksum = calculate_ip_checksum(ip_hdr_no_cksum)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 
                         0x45, 0, total_len, 0, 0x4000, 64, 17, cksum, 
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    
    # UDP Header (8 bytes)
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    
    return eth_hdr + ip_hdr + udp_hdr + payload

class QuaboManager(asyncio.DatagramProtocol):
    """Manages a single persistent UDP socket for all quabos."""
    def __init__(self):
        self.transport = None
        self.pending_requests = {} # (ip, port) -> Future

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # addr is (ip, port)
        future = self.pending_requests.pop(addr, None)
        if future and not future.done():
            future.set_result(data)

    async def trigger_quabo(self, ip, port, timeout=0.5):
        """Sends a trigger to a specific quabo and waits for the response."""
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        addr = (ip, port)
        
        # Safety: check if there's already a pending request for this address
        if addr in self.pending_requests:
            logger.debug(f"Overwriting pending request for {addr}")
            old_future = self.pending_requests.pop(addr)
            if not old_future.done():
                old_future.cancel()

        self.pending_requests[addr] = future
        
        cmd = struct.pack('B', 0x0c) + b'\x00' * 63
        try:
            self.transport.sendto(cmd, addr)
        except OSError as e:
            self.pending_requests.pop(addr, None)
            return None
        
        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self.pending_requests.pop(addr, None)
            return None

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
        self.quabos = self._init_quabos()
        self._validate_quabos()
        
        self.total_generated = 0
        self.generated_since_last_report = 0
        
        self.cycle_count = 0
        self.pcap_writer = None
        self.last_rollover_sec = 0
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.manager = None
        self.transport = None
        self.local_buffer = []
        # Producer-consumer write queue. Bounded to avoid runaway memory if
        # the writer thread falls behind (100 batches ≈ 10 000 packets headroom).
        self._write_queue = asyncio.Queue(maxsize=100)
        self._writer_task = None
        self._watchdog_task = None

    def log(self, level, msg):
        """Custom logging helper that adds telescope scope to every message."""
        getattr(logger, level.lower())(f"[{self.scope}] {msg}")

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
                    self.log("info", f"Resolved {host} to {resolved_ip}")
                except socket.gaierror:
                    self.log("error", f"Could not resolve hostname: {host}")
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
        """
        Dedicated coroutine that drains the write queue and offloads batches to
        the executor thread.  Acquisition never awaits disk I/O directly.
        A sentinel value of None signals clean shutdown.
        """
        loop = asyncio.get_running_loop()
        while True:
            item = await self._write_queue.get()
            if item is None:          # shutdown sentinel
                self._write_queue.task_done()
                break
            writer, batch = item
            try:
                await loop.run_in_executor(self.executor, writer.write_batch, batch)
            except Exception as e:
                self.log("error", f"Disk write error: {e}")
            finally:
                self._write_queue.task_done()

    def _enqueue_batch(self, writer, batch):
        """
        Non-blocking enqueue.  If the queue is full (filesystem stall), the
        oldest item is dropped and a warning is emitted rather than blocking
        the acquisition loop.
        """
        try:
            self._write_queue.put_nowait((writer, batch))
        except asyncio.QueueFull:
            self.log("warning", "Write queue full — dropping oldest batch to protect acquisition timing")
            try:
                self._write_queue.get_nowait()
                self._write_queue.task_done()
            except asyncio.QueueEmpty:
                pass
            try:
                self._write_queue.put_nowait((writer, batch))
            except asyncio.QueueFull:
                self.log("error", "Write queue still full after drop — batch lost")

    def _write_pcap(self, packet, ts_sec, ts_nano):
        """
        Appends one packet to the in-memory buffer.  When the buffer reaches
        the configured size it is handed off to the write queue immediately
        (non-blocking) so acquisition never waits on disk.
        """
        self.local_buffer.append((packet, ts_sec, ts_nano))
        self.log("debug", f"Added packet to local buffer (size={len(self.local_buffer)})")
        if len(self.local_buffer) >= self.args.buffer:
            self._flush_buffer_to_queue()

    def _flush_buffer_to_queue(self):
        """Move the current buffer into the write queue and reset it."""
        if not self.local_buffer or not self.pcap_writer:
            return
        batch = self.local_buffer
        self.local_buffer = []
        self.log("debug", f"Enqueueing {len(batch)} packets for disk write")
        self._enqueue_batch(self.pcap_writer, batch)

    async def _write_pcap_async(self, packet, ts_sec, ts_nano):
        # Thin async shim kept for compatibility — delegates to the sync method.
        self._write_pcap(packet, ts_sec, ts_nano)

    async def _manage_rollover(self, ts_utc):
        """Handles pcapng file rollover. ts_utc is the integer trigger second."""
        if self.pcap_writer is None or ts_utc - self.last_rollover_sec >= self.args.rollover:
            if self.pcap_writer:
                # Enqueue any remaining buffered packets for the old file, then
                # wait for the queue to drain before closing so write_batch and
                # close() can never race on the executor thread.
                self._flush_buffer_to_queue()
                await self._write_queue.join()
                filename = self.pcap_writer.filename
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(self.executor, self.pcap_writer.close)
                self.log("info", f"Closing {filename}, {self.pcap_writer.packets_written} packets written to file.")
            
            dt = datetime.datetime.fromtimestamp(ts_utc)
            filename = self.args.output.format(
                scope=self.scope, date=dt.strftime('%Y%m%d'), time=dt.strftime('%H%M%S')
            )
            self.log("info", f"Opening {filename}")
            self.pcap_writer = PcapngWriter(filename)
            self.local_buffer = []
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
                
            stats_msg = f"Last 60s: {self.generated_since_last_report} pedestal events generated, {miss_str}"
            self.log("info", stats_msg)
            
            # Reset delta stats
            self.generated_since_last_report = 0
            for q in self.quabos:
                q.misses_since_last_report = 0

    async def run(self):
        loop = asyncio.get_running_loop()
        # Initialize the single shared socket
        self.transport, self.manager = await loop.create_datagram_endpoint(
            lambda: QuaboManager(),
            local_addr=('0.0.0.0', self.args.bind_port)
        )
        local_addr = self.transport.get_extra_info('sockname')
        self.log("info", f"Starting pedestal capture at {self.args.frequency} Hz")
        self.log("info", f"Bound to local UDP port {local_addr[1]} (buffer={self.args.buffer})")
        
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
            
        try:
            while True:
                trigger_wall = wall_epoch + (slot + 0.5) / self.args.frequency
                trigger_mono = mono_epoch + (slot + 0.5) / self.args.frequency

                sleep_dur = trigger_mono - time.monotonic()
                if sleep_dur > 0:
                    await asyncio.sleep(sleep_dur)
                elif sleep_dur < -0.1:
                    self.log("warning", f"Cycle {slot} is late by {-sleep_dur:.3f}s")

                self.log("debug", f"Starting cycle {slot}, target trigger time: {trigger_wall:.3f}")
                
                ts_utc = trigger_wall
                ts_tai = int(ts_utc) + self.args.tai_offset
                
                slot_within_second = slot % self.args.frequency
                nanosec = int((slot_within_second + 0.5) / self.args.frequency * 1_000_000_000)

                tasks = [self.manager.trigger_quabo(q.ip, q.port, timeout=timeout) for q in self.quabos]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                await self._manage_rollover(int(ts_utc))
                self.total_generated += 1
                self.generated_since_last_report += 1

                for idx, data in enumerate(results):
                    q = self.quabos[idx]
                    if isinstance(data, Exception):
                        self.log("debug", f"Quabo {idx} error: {data}")
                        data = None

                    if data and len(data) >= 516:
                        self.log("debug", f"Quabo {idx} responded ({len(data)} bytes)")

                        # Log the very first response from each board individually
                        if not q.first_response_logged:
                            self.log("info", f"Quabo {idx} at {q.ip} is responding.")
                            q.first_response_logged = True
                        
                        if q.is_down:
                            self.log("info", f"Quabo {idx} at {q.ip} has recovered.")
                            q.is_down = False
                        q.consecutive_misses = 0
                        
                        boardloc = (self.site_info['module_id'] << 2) | idx
                        science_payload = repack_science_packet(
                            data[4:516], self.cycle_count % 65536, 
                            boardloc, ts_tai, nanosec
                        )
                        full_packet = create_ethernet_ip_udp_packet(
                            science_payload, q.ip, 
                            self.site_info['daq_ip'], 60001, 60001
                        )
                        await self._write_pcap_async(full_packet, int(ts_utc), nanosec)
                    else:
                        self.log("debug", f"Quabo {idx} timeout waiting for response")
                        q.total_missing += 1
                        q.misses_since_last_report += 1
                        q.consecutive_misses += 1
                        if q.consecutive_misses >= 5 and not q.is_down:
                            self.log("warning", f"Quabo {idx} at {q.ip} is not responding (5 consecutive misses). It might be down.")
                            q.is_down = True
                
                self.cycle_count += 1
                slot += 1
        finally:
            # ----------------------------------------------------------------
            # Clean shutdown: flush remaining data, drain the queue, then close.
            # ----------------------------------------------------------------
            self._flush_buffer_to_queue()

            # Signal the writer task to exit after draining
            await self._write_queue.put(None)
            try:
                await asyncio.wait_for(self._writer_task, timeout=10.0)
            except asyncio.TimeoutError:
                self.log("error", "Writer task did not finish in time — some data may be lost")
                self._writer_task.cancel()

            if self.pcap_writer:
                try:
                    filename = self.pcap_writer.filename
                    count = self.pcap_writer.packets_written
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(self.executor, self.pcap_writer.close)
                    self.log("info", f"Closing {filename}, {count} packets written to file.")
                except Exception as e:
                    self.log("error", f"Error closing pcap file: {e}")

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
    parser.add_argument('--buffer', type=int, default=100, help='Number of packets to buffer before writing to disk (>= 1).')
    parser.add_argument('--log-level', default='INFO', help='Logging level (DEBUG, INFO, WARNING, ERROR)')
    parser.add_argument('--timeout', type=float, default=None, help=f'UDP response timeout in seconds (default: max({MIN_TIMEOUT}, 0.5/frequency))')
    parser.add_argument('--quabos', nargs='+', help='List of quabo addresses in host[:port] format. Overrides site defaults.')
    args = parser.parse_args()

    # ---- Argument validation ----
    if not (1 <= args.frequency <= MAX_FREQUENCY):
        parser.error(f'--frequency must be between 1 and {MAX_FREQUENCY}')
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
