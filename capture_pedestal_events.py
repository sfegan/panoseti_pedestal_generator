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

def repack_science_packet(pixel_data, packet_no, boardloc, tai_seconds, nanoseconds):
    """Repacks 256 pixel values into a 528-byte PANOSETI science packet."""
    # Offset 0: acq_mode = 0x01 (PH)
    # Offset 1: packet_ver = 1 (16-bit signed PH)
    header = struct.pack('<BBHHIIH', 
                         0x01, 1, packet_no, boardloc, 
                         tai_seconds, nanoseconds, 0)
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
        'scope': 'localhost',
        'use_ports': True
    }
}

class PcapngWriter:
    """Minimal Pcapng writer with support for SHB, IDB, and EPB."""
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'wb')
        self._write_shb()
        self._write_idb()

    def _write_shb(self):
        # Section Header Block (SHB)
        shb_body = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
        shb_len = 12 + len(shb_body) + 4
        shb_block = struct.pack('<II', 0x0A0D0D0A, shb_len) + shb_body + struct.pack('<I', shb_len)
        self.file.write(shb_block)

    def _write_idb(self):
        # Interface Description Block (IDB)
        idb_body = struct.pack('<HHI', 1, 0, 65535)
        idb_len = 12 + len(idb_body) + 4
        idb_block = struct.pack('<II', 0x00000001, idb_len) + idb_body + struct.pack('<I', idb_len)
        self.file.write(idb_block)

    def write_packet(self, data, ts_seconds, ts_nanoseconds):
        # Enhanced Packet Block (EPB)
        ts_micros = int(ts_seconds * 1_000_000 + ts_nanoseconds / 1000)
        ts_high = ts_micros >> 32
        ts_low = ts_micros & 0xFFFFFFFF
        
        cap_len = len(data)
        padding_len = (4 - (cap_len % 4)) % 4
        
        epb_len = 32 + cap_len + padding_len + 4
        
        # Build the entire EPB block in memory
        block_parts = [
            struct.pack('<IIIIIII', 0x00000006, epb_len, 0, ts_high, ts_low, cap_len, cap_len),
            data,
            b'\x00' * padding_len,
            struct.pack('<I', epb_len)
        ]
        self.file.write(b''.join(block_parts))
        self.file.flush()

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

def create_ethernet_ip_udp_packet(payload, src_ip, dst_ip, src_port, dst_port):
    """Wraps payload in Ethernet, IPv4, and UDP headers."""
    # Ethernet Header (14 bytes)
    eth_hdr = struct.pack('!6s6sH', b'\x00'*6, b'\x00'*6, 0x0800)
    
    # IPv4 Header (20 bytes)
    total_len = 20 + 8 + len(payload)
    ip_hdr = struct.pack('!BBHHHBBH4s4s', 
                         0x45, 0, total_len, 0, 0x4000, 64, 17, 0, 
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    
    # UDP Header (8 bytes)
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    
    return eth_hdr + ip_hdr + udp_hdr + payload

class QuaboProtocol(asyncio.DatagramProtocol):
    def __init__(self, future):
        self.future = future
    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

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

    async def trigger_quabo(self, ip, port, timeout=0.1):
        """Sends a trigger to a specific quabo and waits for the response."""
        loop = asyncio.get_event_loop()
        future = loop.create_future()
        addr = (ip, port)
        
        # In case of multiple quabos on same IP (like localhost testing)
        # We need a way to distinguish them if they share the same addr.
        # But for quabos, addr IS the unique identifier.
        self.pending_requests[addr] = future
        
        cmd = struct.pack('B', 0x0c) + b'\x00' * 63
        self.transport.sendto(cmd, addr)
        
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
        self.missing_count = 0

class PedestalGenerator:
    def __init__(self, args):
        self.args = args
        self.site_info = SITES[args.site]
        self.quabos = self._init_quabos()
        self.total_generated = 0
        self.cycle_count = 0
        self.pcap_writer = None
        self.last_rollover = 0
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        self.manager = None
        self.transport = None

    def _init_quabos(self):
        clients = []
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

    async def _write_pcap_async(self, packet, ts_sec, ts_nano):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self.pcap_writer.write_packet, packet, ts_sec, ts_nano)

    async def _manage_rollover(self, ts_utc):
        if self.pcap_writer is None or ts_utc - self.last_rollover > self.args.rollover:
            if self.pcap_writer:
                self.pcap_writer.close()
            dt = datetime.datetime.fromtimestamp(ts_utc)
            filename = self.args.output.format(
                scope=self.site_info['scope'], date=dt.strftime('%Y%m%d'), time=dt.strftime('%H%M%S')
            )
            logger.info(f"Rolling over to {filename}")
            self.pcap_writer = PcapngWriter(filename)
            self.last_rollover = ts_utc

    async def watchdog_task(self):
        while True:
            await asyncio.sleep(180)
            missing = [q.missing_count for q in self.quabos]
            logger.info(f"Status: Total={self.total_generated}, Missing={missing}")

    async def run(self):
        loop = asyncio.get_event_loop()
        # Initialize the single shared socket
        self.transport, self.manager = await loop.create_datagram_endpoint(
            lambda: QuaboManager(),
            local_addr=('0.0.0.0', self.args.bind_port)
        )
        local_addr = self.transport.get_extra_info('sockname')
        logger.info(f"Starting pedestal capture for {self.site_info['scope']} at {self.args.frequency} Hz")
        logger.info(f"Bound to local UDP port {local_addr[1]}")
        
        watchdog = asyncio.ensure_future(self.watchdog_task())

        try:
            while True:
                now = time.time()
                sec_start = int(now)
                k = 0
                while True:
                    trigger_time = sec_start + (k + 0.5) / self.args.frequency
                    if trigger_time > now:
                        break
                    k += 1
                
                await asyncio.sleep(trigger_time - time.time())
                
                ts_utc = trigger_time
                ts_tai = int(ts_utc) + self.args.tai_offset
                nanosec = int(((k % self.args.frequency) + 0.5) / self.args.frequency * 1_000_000_000)

                # Trigger all quabos concurrently using the shared manager
                tasks = [self.manager.trigger_quabo(q.ip, q.port) for q in self.quabos]
                results = await asyncio.gather(*tasks)

                await self._manage_rollover(ts_utc)

                for idx, data in enumerate(results):
                    if data and len(data) >= 516:
                        boardloc = (self.site_info['module_id'] << 2) | idx
                        science_payload = repack_science_packet(
                            data[4:516], self.cycle_count % 65536, 
                            boardloc, ts_tai, nanosec
                        )
                        full_packet = create_ethernet_ip_udp_packet(
                            science_payload, self.quabos[idx].ip, 
                            self.site_info['daq_ip'], 60001, 60001
                        )
                        await self._write_pcap_async(full_packet, int(ts_utc), nanosec)
                        self.total_generated += 1
                    else:
                        self.quabos[idx].missing_count += 1
                
                self.cycle_count += 1
        finally:
            watchdog.cancel()
            if self.pcap_writer:
                self.pcap_writer.close()
            if self.transport:
                self.transport.close()
            self.executor.shutdown()

async def main():
    parser = argparse.ArgumentParser(description='PANOSETI Pedestal Capture')
    parser.add_argument('--site', '-s', required=True, choices=SITES.keys(), help='Telescope site')
    parser.add_argument('--frequency', type=int, default=1, help='Polling frequency in Hz')
    parser.add_argument('--rollover', type=int, default=600, help='File rollover interval in seconds')
    parser.add_argument('--output', '-o', default='pedestals_{scope}_{date}_{time}.pcapng', help='Output filename template')
    parser.add_argument('--tai-offset', type=int, default=37, help='TAI offset from UTC')
    parser.add_argument('--bind-port', type=int, default=0, help='Local UDP port to bind to (0 for random)')
    args = parser.parse_args()

    generator = PedestalGenerator(args)
    await generator.run()

if __name__ == "__main__":
    # Python 3.7+ has asyncio.run, but we maintain 3.6 compatibility
    if hasattr(asyncio, 'run'):
        try:
            asyncio.run(main())
        except KeyboardInterrupt:
            pass
    else:
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(main())
        except KeyboardInterrupt:
            pass
        finally:
            loop.close()
