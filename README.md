# SMS Testing Tool

A Python-based SMS testing tool that allows sending customized SMS messages through a GSM modem. This tool supports various testing scenarios including fuzzing, SIM toolkit commands, and custom payloads.

## Features

- Send custom SMS messages in PDU format
- Multiple payload options (hex string, file, random, SIM toolkit commands)
- Advanced fuzzing capabilities with multiple strategies
- Support for Flash SMS and other special message types
- Configurable serial port settings
- Comprehensive logging system
- SHA256 hash verification
- Loop testing capabilities

## Prerequisites

- Python 3.6+
- PySerial library
- GSM modem (USB or Serial)
- Windows/Linux compatible

## Installation

1. Install required Python package:
```bash
pip install pyserial
