# PANOSETI Pedestal Generator

This repository contains a tool to trigger and capture pedestal events from PANOSETI detector modules:
- `capture_pedestal_events.py`: Polls detector boards (Quabos) for software-generated Pulse Height pedestals events, wraps the payloads in Ethernet/IP/UDP headers, and writes them to a `.pcapng` file.
- `quabo_emulator.py`: Emulates four Quabo boards responding to SW PH trigger commands with normal-distributed random pixel values for testing.

---

## Pedestal Events

Pedestal events sample the baseline pixel amplitudes when no trigger is present. These can be used downstream to estimate the average baseline per pixel and its variance. These are used in a gamma-ray analysis to subtract the baseline during pulse analysis and to fit the pointing model based on the contribution of starlist to the pixel variance. Exterally generated pedestal events improve the measurement of these values by increasing the sampling to any desired rate, independent of the actual trigger rate of the system.

---

## How It Works

`capture_pedestal_events.py` polls a module of four Quabo boards (each processing 256 pixels) and records the responses.

### 1. Timing and Scheduling
The script uses a software-based phase-locked loop to schedule polling times relative to the system clock. Triggers are scheduled at:
$$\text{Trigger Time} = \text{Epoch} + \frac{\text{Slot} + 0.5}{\text{Frequency}}$$
The script sleeps using `asyncio.sleep` until the scheduled time. If a cycle is delayed by more than 0.1 seconds, a warning is logged.

### 2. UDP Polling
The script binds to a single local UDP port using an `asyncio.DatagramProtocol` subclass (`QuaboManager`).
* In each cycle, it sends the 64-byte "SW_PH" command (first byte `0x0c` followed by zeros) to the four configured Quabo boards concurrently.
* It waits for responses with a configurable timeout (defaulting to $0.5 / \text{frequency}$).
* Responses are matched to pending requests using the sender's `(IP, Port)` address.

### 3. Packet Format & Repacking
Raw response packets contain a 4-byte header and 512 bytes of pixel data (256 channels of 16-bit signed integers). The script repacks this data into a 528-byte PANOSETI Science Packet:

| Offset (Bytes) | Size | Field Name | Value / Description |
| :--- | :--- | :--- | :--- |
| `0` | 1B | `acq_mode` | `0x01` (Pulse Height) |
| `1` | 1B | `packet_ver` | `1` (16-bit signed PH) |
| `2` | 2B | `packet_no` | 16-bit sequence number (Little-Endian) |
| `4` | 2B | `boardloc` | Location ID: `(Module ID << 2) \| Quadrant` |
| `6` | 4B | `TAI` | TAI seconds since epoch (`UTC + tai_offset`) |
| `10` | 4B | `NANOSEC` | Sub-second trigger time in nanoseconds |
| `14` | 2B | *Reserved* (or *Flags*?) | 0x0001 |
| `16` | 512B | `pixel_data` | 256 pixel values (16-bit signed integers) |

**Note:** I propose that the *Reserved* field be considered as a *Flags* field in the future, allowing for future expansion without breaking compatibility. Here I propose that bit 0 (LSB) be used to indicate whether the payload contains a software triggered event.

### 4. Ethernet/IP/UDP Encapsulation
To match the format of physical network captures, the 528-byte science payload is wrapped in standard headers:
* **Ethernet II Header** (14 bytes): Source and destination MAC addresses are set to zero. EtherType is `0x0800` (IPv4).
* **IPv4 Header** (20 bytes): Uses the configured Quabo IP as source, DAQ IP as destination, and computes the 16-bit one's complement Internet checksum.
* **UDP Header** (8 bytes): Uses port `60001` for source and destination. The UDP checksum field is set to zero.

The resulting mock network packet is 570 bytes.

### 5. File Output (`PcapngWriter`)
* **Nanosecond Precision**: The output `pcapng` file is written with an Interface Description Block configuring a time resolution of $10^{-9}$ seconds.
* **Buffered Writes**: Packets are buffered in memory. When the buffer reaches `--buffer` packets, they are written to disk in a single operation using a background thread (`concurrent.futures.ThreadPoolExecutor`) to prevent disk I/O from blocking the asynchronous timing loop.
* **Rollover**: The capture file is closed and a new one is opened after `--rollover` seconds. Files are named using the template: `pedestals_{scope}_{date}_{time}.pcapng`.

### 6. Diagnostics and Watchdog
* **Watchdog**: A background task logs statistics every 60 seconds, displaying the number of generated pedestals and any missed packets per board.
* **Timeout Detection**: If a board fails to respond for 5 consecutive cycles, a warning is logged. A recovery message is logged once communication resumes.

---

## Site Configurations

Presets configure the Quabo IP addresses, DAQ IP address, and module ID:
* For physical sites, Quabo boards are assumed to have sequential IP addresses starting from `base_ip` (Quadrant 0 to 3) on port `60000`.
* For `localhost`, all four boards run on `127.0.0.1` using ports `60000` to `60003`.

| Preset | Site Name | Base IP | DAQ IP | Module ID | Mode |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `gattini` | Gattini | `192.168.3.248` | `192.168.0.4` | `254` | Sequential IPs |
| `winter` | Winter | `192.168.3.244` | `192.168.0.6` | `253` | Sequential IPs |
| `fern` | Fern | `192.168.3.240` | `192.168.0.9` | `252` | Sequential IPs |
| `pti` | PTI | `192.168.3.232` | `192.168.0.8` | `250` | Sequential IPs |
| `localhost` | Emulator | `127.0.0.1` | `127.0.0.1` | `0` | Sequential Ports |

---

## Command Line Arguments

| Argument | Shorthand | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--site` | `-s` | *String* | **Required** | Preset choice (`gattini`, `winter`, `fern`, `pti`, `localhost`) |
| `--frequency` | | *Int* | `1` | Polling frequency in Hz |
| `--rollover` | | *Int* | `600` | Rollover interval in seconds |
| `--output` | `-o` | *String* | `pedestals_{scope}_{date}_{time}.pcapng` | Output path template |
| `--tai-offset` | | *Int* | `37` | TAI offset from UTC in seconds |
| `--bind-port` | | *Int* | `0` | Local port to bind (0 for random ephemeral port) |
| `--buffer` | | *Int* | `100` | Number of packets to buffer before disk write |
| `--log-level` | | *String* | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--timeout` | | *Float* | `None` | UDP timeout in seconds (defaults to $0.5 / \text{frequency}$) |

---

## Running Locally

To test the capture utility locally using the emulator:

### 1. Start the Emulator
Run the emulator to simulate four Quabo boards on `127.0.0.1` listening on ports `60000` to `60003`:
```bash
python3 quabo_emulator.py --delay 0.002 --drop-prob 0.01
```
* `--delay 0.002` sets a 2 ms response delay.
* `--drop-prob 0.01` simulates a 1% packet loss rate.

### 2. Start the Capture Utility
In a separate terminal, run the capture utility using the `localhost` preset:
```bash
python3 capture_pedestal_events.py --site localhost --frequency 4 --buffer 10 --rollover 60
```
* `--site localhost` targets the local emulated ports.
* `--frequency 4` sets the polling rate to 4 Hz.
* `--buffer 10` flushes packets to disk in batches of 10.
* `--rollover 60` rolls over to a new file every 60 seconds.

## References:

- [PANOSETI quabo packet interface](https://github.com/panoseti/panoseti/wiki/Quabo-packet-interface)
- [PANOSET control_quabo.py test script](https://github.com/panoseti/panoseti/blob/master/control/test_scripts/control_quabo.py) (see "R-PH" command handling)