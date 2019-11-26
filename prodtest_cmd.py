#!/usr/bin/python

import os
import sys
import argparse
import os.path
import serial
from array import *

VERSION     = 0
SUBVERSION  = 1

HCI_PKT_INDICATOR_COMMAND           = '01'
HCI_PKT_INDICATOR_ACL_DATA          = '02'
HCI_PKT_INDICATOR_SYNCHRONOUS_DATA  = '03'
HCI_PKT_INDICATOR_EVENT             = '04'

VS_PKT_INDICATOR_COMMAND            = '41'  # char 'A'

HCI_EVENTCODE_HCI_COMMAND_COMPLETE  = '0E'

HCI_OPCODE_HCI_RESET                = '0C03'
HCI_OPCODE_HCI_LE_RECEIVER_TEST     = '201D'
HCI_OPCODE_HCI_LE_TRANSMITTER_TEST  = '201E'
HCI_OPCODE_HCI_LE_TEST_END          = '201F'

ACTION_LIST_ENTRY0                  = 0


dict_error_codes = {
    '00' : 'Success',
    '01' : 'Unknown HCI Command',
    '02' : 'Unknown Connection Identifier',
    '03' : 'Hardware Failure',
    '04' : 'Page Timeout',
    '05' : 'Authentication Failure',
    '06' : 'PIN or Key Missing',
    '07' : 'Memory Capacity Exceeded',
    '08' : 'Connection Timeout',
    '09' : 'Connection Limit Exceeded',
    '0A' : 'Synchronous Connection Limit To A Device Exceeded',
    '0B' : 'Connection Already Exists',
    '0C' : 'Command Disallowed',
    '0D' : 'Connection Rejected due to Limited Resources',
    '0E' : 'Connection Rejected Due To Security Reasons',
    '0F' : 'Connection Rejected due to Unacceptable BD_ADDR',
    '10' : 'Connection Accept Timeout Exceeded',
    '11' : 'Unsupported Feature or Parameter Value',
    '12' : 'Invalid HCI Command Parameters',
    '13' : 'Remote User Terminated Connection',
    '14' : 'Remote Device Terminated Connection due to Low Resources',
    '15' : 'Remote Device Terminated Connection due to Power Off',
    '16' : 'Connection Terminated By Local Host',
    '17' : 'Repeated Attempts',
    '18' : 'Pairing Not Allowed',
    '19' : 'Unknown LMP PDU',
    '1A' : 'Unsupported Remote Feature / Unsupported LMP Feature',
    '1B' : 'SCO Offset Rejected',
    '1C' : 'SCO Interval Rejected',
    '1D' : 'SCO Air Mode Rejected',
    '1E' : 'Invalid LMP Parameters / Invalid LL Parameters',
    '1F' : 'Unspecified Error',
    '20' : 'Unsupported LMP Parameter Value / Unsupported LL Parameter Value',
    '21' : 'Role Change Not Allowed',
    '22' : 'LMP Response Timeout / LL Response Timeout',
    '23' : 'LMP Error Transaction Collision / LL Procedure Collision',
    '24' : 'LMP PDU Not Allowed',
    '25' : 'Encryption Mode Not Acceptable',
    '26' : 'Link Key cannot be Changed',
    '27' : 'Requested QoS Not Supported',
    '28' : 'Instant Passed',
    '29' : 'Pairing With Unit Key Not Supported',
    '2A' : 'Different Transaction Collision',
    '2B' : 'Reserved for future use',
    '2C' : 'QoS Unacceptable Parameter',
    '2D' : 'QoS Rejected',
    '2E' : 'Channel Classification Not Supported',
    '2F' : 'Insufficient Security',
    '30' : 'Parameter Out Of Mandatory Range',
    '31' : 'Reserved for future use',
    '32' : 'Role Switch Pending',
    '33' : 'Reserved for future use',
    '34' : 'Reserved Slot Violation',
    '35' : 'Role Switch Failed',
    '36' : 'Extended Inquiry Response Too Large',
    '37' : 'Secure Simple Pairing Not Supported By Host',
    '38' : 'Host Busy - Pairing',
    '39' : 'Connection Rejected due to No Suitable Channel Found',
    '3A' : 'Controller Busy',
    '3B' : 'Unacceptable Connection Parameters',
    '3C' : 'Advertising Timeout',
    '3D' : 'Connection Terminated due to MIC Failure',
    '3E' : 'Connection Failed to be Established / Synchronization Timeout',
    '3F' : 'MAC Connection Failed',
    '40' : 'Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging',
    '41' : 'Type0 Submap Not Defined',
    '42' : 'Unknown Advertising Identifier',
    '43' : 'Limit Reached',
    '44' : 'Operation Cancelled by Host',
    '45' : 'Packet Too Long',
}

# ++++++++++++++++++++++++++++++++++++++++++++++++++++
# Callbacks in the dictionary dict_opcodes
def HCI_Reset_parser(args, rawdata):
    # nothing to do for this command. A place holder here.
    return None

def HCI_LE_Receiver_Test_parser(args, rawdata):

    HCI_LE_RECEIVER_TEST_COMMAND_PARAMETERS_RX_CHANNEL_OFFSET = 0

    return 'Rx Channel: 0x{:02X}'.format(rawdata[HCI_LE_RECEIVER_TEST_COMMAND_PARAMETERS_RX_CHANNEL_OFFSET])

def HCI_LE_Transmitter_Test_parser(args, rawdata):

    dict_transmitter_test_pkt_payloads = {
        '00' : 'PRBS9',
        '01' : '11110000',
        '02' : '10101010',
        '03' : 'PRBS15',
        '04' : '11111111',
        '05' : '00000000',
        '06' : '00001111',
        '07' : '01010101',
        '08' : 'Carrier Wave (propietary)',
        '09' : 'Continuous Modulated Signla (propietary)',
    }

    HCI_LE_TRANSMITTER_TEST_COMMAND_PARAMETERS_TX_CHANNEL_OFFSET            = 0
    HCI_LE_TRANSMITTER_TEST_COMMAND_PARAMETERS_LENGTH_OF_TEST_DATA_OFFSET   = 1
    HCI_LE_TRANSMITTER_TEST_COMMAND_PARAMETERS_PACKET_PAYLOAD_OFFSET        = 2
    
    ret =   'Tx Channel: 0x{:02X},'.format(rawdata[HCI_LE_TRANSMITTER_TEST_COMMAND_PARAMETERS_TX_CHANNEL_OFFSET])
    ret +=  ' Length of Test Data: 0x{:02X},'.format(rawdata[HCI_LE_TRANSMITTER_TEST_COMMAND_PARAMETERS_LENGTH_OF_TEST_DATA_OFFSET])

    pkt_payload = ''.join('{:02X}'.format(rawdata[HCI_LE_TRANSMITTER_TEST_COMMAND_PARAMETERS_PACKET_PAYLOAD_OFFSET]))

    dict_transmitter_test_pkt_payloads.get(pkt_payload, 'Not recognized')
    ret +=  ' Packet Payload: 0x{} ({})'.format(pkt_payload, dict_transmitter_test_pkt_payloads.get(pkt_payload, 'Not recognized'))
    return ret

def HCI_LE_Test_End_parser(args, rawdata):
    # nothing to do for this command. More like a place holder here.
    return None
# ----------------------------------------------------

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Callbacks in the dictionary dict_hci_command_complete_return_params
def HCI_Reset_Return_Parameters_parser(args, rawdata):

    HCI_RESET_RETURN_PARAM_STATUS_OFFSET = 0

    status = ''.join('{:02X}'.format(rawdata[HCI_RESET_RETURN_PARAM_STATUS_OFFSET]))

    ret = 'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{})'.format(status)

    return ret

def HCI_LE_Receiver_Test_Return_Parameters_parser(args, rawdata):

    HCI_LE_RECEIVER_TEST_RETURN_PARAM_STATUS_OFFSET = 0

    status = ''.join('{:02X}'.format(rawdata[HCI_LE_RECEIVER_TEST_RETURN_PARAM_STATUS_OFFSET]))

    ret = 'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{})'.format(status)

    return ret

def HCI_LE_Transmitter_Test_Return_Parameters_parser(args, rawdata):

    HCI_LE_TRANSMITTER_TEST_RETURN_PARAM_STATUS_OFFSET = 0

    status = ''.join('{:02X}'.format(rawdata[HCI_LE_TRANSMITTER_TEST_RETURN_PARAM_STATUS_OFFSET]))

    ret = 'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{})'.format(status)
    return ret

def HCI_LE_Test_End_Return_Parameters_parser(args, rawdata):

    HCI_LE_TEST_END_RETURN_PARAM_STATUS_OFFSET = 0
    HCI_LE_TEST_END_RETURN_PARAM_NUMBER_OF_PACKETS_OFFSET = 1

    status = ''.join('{:02X}'.format(rawdata[HCI_LE_TEST_END_RETURN_PARAM_STATUS_OFFSET]))

    num_of_pkt_recv = ''.join('{:02X}'.format(rawdata[HCI_LE_TEST_END_RETURN_PARAM_NUMBER_OF_PACKETS_OFFSET + 1])) + \
                ''.join('{:02X}'.format(rawdata[HCI_LE_TEST_END_RETURN_PARAM_NUMBER_OF_PACKETS_OFFSET]))

    ret =   'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{}), '.format(status)

    if args.log is True:
        ret +=  'Number of packets received: ' + '(0x{}), '.format(num_of_pkt_recv)

    return ret
# -------------------------------------------------------------------

# Name, command assembler, command parser, response parser
dict_opcodes = {
    HCI_OPCODE_HCI_RESET                : ('HCI_Reset',               None, HCI_Reset_parser,                 HCI_Reset_Return_Parameters_parser),
    HCI_OPCODE_HCI_LE_RECEIVER_TEST     : ('HCI_LE_Receiver_Test',    None, HCI_LE_Receiver_Test_parser,      HCI_LE_Receiver_Test_Return_Parameters_parser),
    HCI_OPCODE_HCI_LE_TRANSMITTER_TEST  : ('HCI_LE_Transmitter_Test', None, HCI_LE_Transmitter_Test_parser,   HCI_LE_Transmitter_Test_Return_Parameters_parser),
    HCI_OPCODE_HCI_LE_TEST_END          : ('HCI_LE_Test_End',         None, HCI_LE_Test_End_parser,           HCI_LE_Test_End_Return_Parameters_parser),
}

# ++++++++++++++++++++++++++++++++++++++++++++++++++++
# Callbacks in the dictionary dict_hci_pkt_event_codes
def HCI_Command_Complete_parser(args, rawdata):

    EVENT_PARAM_NUM_HCI_COMMAND_PACKETS_OFFSET = 0
    EVENT_PARAM_COMMAND_OPCODE_OFFSET = 1
    EVENT_PARAM_RETURN_PARAM_OFFSET = 3

    opcode = ''.join('{:02X}'.format(rawdata[EVENT_PARAM_COMMAND_OPCODE_OFFSET + 1])) + \
                ''.join('{:02X}'.format(rawdata[EVENT_PARAM_COMMAND_OPCODE_OFFSET]))

    (description, cmd_assembler, cmd_parser, rsp_parser) = dict_opcodes.get(opcode, ("Invalid", None, None, None))

    if rsp_parser is not None:
        parsed_opcode_rsp_str = rsp_parser(args, rawdata[EVENT_PARAM_RETURN_PARAM_OFFSET:])

        if args.log is True:
            ret =   '\tHCI_Command_Complete\r\n'
            ret +=  '\t[Number HCI Command Packets] 0x{:02X}\r\n'.format(rawdata[EVENT_PARAM_NUM_HCI_COMMAND_PACKETS_OFFSET])
            ret +=  '\t[OpCode] {} (0x{})\r\n'.format(description, opcode)
            ret +=  '\t[Return] {}'.format(parsed_opcode_rsp_str)
        else:
            ret = parsed_opcode_rsp_str
    else:
        ret =   '\tNo parser available for Opcode 0x{}\r\n'.format(opcode)

    return ret
# ----------------------------------------------------

# ++++++++++++++++++++++++++++++++++++++++++++++
# Callbacks in the dictionary dict_hci_pkt_types
def pkt_cmd_assembler(args, rawdata):
    print ("[TODO] pkt_cmd_assembler")

def pkt_cmd_parser(args, rawdata):

    HCI_PKT_CMD_OPCODE_OFFSET                   = 0
    HCI_PKT_CMD_PARAMETER_TOTAL_LENGTH_OFFSET   = 2
    HCI_PKT_CMD_PARAMETER                       = 3

    opcode = ''.join('{:02X}'.format(rawdata[HCI_PKT_CMD_OPCODE_OFFSET + 1])) + \
                ''.join('{:02X}'.format(rawdata[HCI_PKT_CMD_OPCODE_OFFSET]))

    (description, cmd_assembler, cmd_parser, rsp_parser) = dict_opcodes.get(opcode, ("Invalid", None, None, None))

    if cmd_parser is not None:

        ret =   '\t[OpCode] {} (0x{})\r\n'.format(description, opcode)
        ret +=  '\t[Parameter Total Length] 0x{:02X}\r\n'.format(rawdata[HCI_PKT_CMD_PARAMETER_TOTAL_LENGTH_OFFSET])

        if rawdata[HCI_PKT_CMD_PARAMETER_TOTAL_LENGTH_OFFSET] > 0:
            parsed_opcode_str = cmd_parser(args, rawdata[HCI_PKT_CMD_PARAMETER:])
            ret += '\t[Parameters] {}\r\n'.format(parsed_opcode_str)

    else:
            ret = '\tNo parser available for Opcode 0x{}\r\n'.format(opcode)

    return ret

def pkt_event_assembler(args, rawdata):
    print ("[TODO] pkt_event_assembler")

def pkt_event_parser(args, rawdata):

    dict_hci_pkt_event_codes = {
        HCI_EVENTCODE_HCI_COMMAND_COMPLETE : ('HCI_Command_Complete', HCI_Command_Complete_parser),
    }

    HCI_PKT_EVENT_EVENT_CODE_OFFSET         = 0
    HCI_PKT_EVENT_PARAM_TOTAL_LEN_OFFSET    = 1
    HCI_PKT_EVENT_EVENT_PARAM_OFFSET        = 2

    code = ''.join('{:02X}'.format(rawdata[HCI_PKT_EVENT_EVENT_CODE_OFFSET]))
    (event_name, parser) = dict_hci_pkt_event_codes.get(code, (None, None))

    if parser is not None:
        ret = parser(args, rawdata[HCI_PKT_EVENT_EVENT_PARAM_OFFSET:])

    return ret

def vspkt_cmd_parser(args, rawdata):
    # TODO
    return None


dict_hci_pkt_types = {
    HCI_PKT_INDICATOR_COMMAND   : (None, pkt_cmd_parser),
    HCI_PKT_INDICATOR_EVENT     : (None, pkt_event_parser),
    VS_PKT_INDICATOR_COMMAND    : (None, None),
}
# ----------------------------------------------

# ++++++++++++++++++++++++++++++++++++++++
# Callbacks in the dictionary dict_actions
def reset_handler(args):
    return bytearray(b'\x01\x03\x0C\x00')

def start_tx_handler(args):

    if args.freq in range(0, 40):
        # Insert the frequency index to cmd[-2]
        cmd = bytearray(b'\x01\x1E\x20\x03\x25\x00')

        cmd.insert(-2, args.freq)

        return cmd

    else:
        return None

def start_tx_cw_handler(args):

    if args.freq in range(0, 40):
        # Insert the frequency index to cmd[-2]
        cmd = bytearray(b'\x01\x1E\x20\x03\x25\x08')

        cmd.insert(-2, args.freq)

        return cmd

    else:
        return None

def start_tx_cont_handler(args):

    if args.freq in range(0, 40):
        # Insert the frequency index to cmd[-2]
        cmd = bytearray(b'\x01\x1E\x20\x03\x25\x09')

        cmd.insert(-2, args.freq)

        return cmd

    else:
        return None

def start_rx_handler(args):

    if args.freq in range(0, 40):
        cmd = bytearray(b'\x01\x1D\x20\x01')

        cmd.append(args.freq)

        return cmd

    else:
        return None

def stop_test_handler(args):

    return bytearray(b'\x01\x1F\x20\x00')

def set_xtrim_handler(args):

    cmd = bytearray(b'\x41\x4D\x31') + int(args.action[1]).to_bytes(2, byteorder='big')

    return cmd
# ----------------------------------------


def send_cmd(args, ser):

    dict_actions = {
        'reset'         : ('Reset DUT',                             reset_handler),
        'start_tx'      : ('Start TX Test',                         start_tx_handler),
        'start_tx_cw'   : ('Start TX Carrier Wave',                 start_tx_cw_handler),
        'start_tx_cont' : ('Start TX Continuous Modulated Signal',  start_tx_cont_handler),
        'start_rx'      : ('Start RX Test',                         start_rx_handler),
        'stop_test'     : ('Stop Test',                             stop_test_handler),
        'set_xtrim'     : ('Set 32MHz Trim Value',                  set_xtrim_handler),
    }

    HCI_PKT_INDICATOR_OFFSET    = 0
    HCI_PKT_PAYLOAD_OFFSET      = 1

    (description, handler) = dict_actions.get(args.action[ACTION_LIST_ENTRY0], None)

    if handler is not None:
        cmd = handler(args)

        if cmd is not None:
            if args.log is True:
                print ('<<', ' '.join('0x{:02X}'.format(x) for x in cmd))

                pkt_type = ''.join('{:02X}'.format(cmd[HCI_PKT_INDICATOR_OFFSET]))

                (assembler, parser) = dict_hci_pkt_types.get(pkt_type, (None, None))

                if parser is not None:
                    ret = parser(args, cmd[HCI_PKT_PAYLOAD_OFFSET:])

                    print (ret)

            else:
                print ('{}'.format(description))

            ser.write(cmd)

    else:
        print ('{} not supported'.format(args.action))

def recv_rsp(args, ser):

    HCI_PKT_INDICATOR_OFFSET    = 0
    HCI_PKT_PAYLOAD_OFFSET      = 1

    res = ser.read(1000)

    if len(res) > 0:
        if args.log is True:
            print ('>>', ' '.join('0x{:02X}'.format(x) for x in res))

        pkt_type = ''.join('{:02X}'.format(res[HCI_PKT_INDICATOR_OFFSET]))

        (assembler, parser) = dict_hci_pkt_types.get(pkt_type, (None, None))

        if parser is not None:
            ret = parser(args, res[HCI_PKT_PAYLOAD_OFFSET:])

        else:
            ret = 'No parser available for HCI Packet Type 0x{}'.format(pkt_type)

        print (ret)


def usage(name=None):                                                            
    return '''
        Reset DUT\t\t\t\t: prodtest_cmd.py -p <COM> -a reset
        Stop Test\t\t\t\t: prodtest_cmd.py -p <COM> -a stop_test
        Start TX Test\t\t\t\t: prodtest_cmd.py -p <COM> -a start_tx -f <FREQ>
        Start TX Carrier Wave\t\t\t: prodtest_cmd.py -p <COM> -a start_tx_cw -f <FREQ>
        Start TX Continuous Modulated Signal\t: prodtest_cmd.py -p <COM> -a start_tx_cont -f <FREQ>
        Start RX test\t\t\t\t: prodtest_cmd.py -p <COM> -a start_rx -f <FREQ>
        Set XTrim Value\t\t\t\t: prodtest_cmd.py -p <COM> -a set_xtrim <VALUE>
        Help\t\t\t\t\t: prodtest_cmd.py -h
        '''

def main():

    parser = argparse.ArgumentParser(
        description = 'This program controls DUT, running the project uart_ble_bridge, in BLE direct test mode (DTM) via a given serial port.',
        usage = usage(),
        )

    parser.add_argument('-p', '--port',
                        dest        = 'port',
                        required    = True,
                        type        = str,
                        help        = 'Serial port',
                        )

    parser.add_argument('-a', '--action',
                        dest        = 'action',
                        required    = True,
                        type        = str,
                        nargs       = '*',
                        help        = 'Actions to be performed.',
                        )

    parser.add_argument('-f', '--freq',
                        dest        = 'freq',
                        required    = False,
                        type        = int,
                        default     = -1,
                        help        = 'Channle Index(0 to 39) to be tested.',
                        )

    parser.add_argument('-l', '--log',
                        dest        = 'log',
                        required    = False,
                        action      = 'store_true',
                        help        = 'Enable logging',
                        )

    parser.add_argument('-v', '--version',
                        help        = 'show the program version',
                        action      = 'version',
                        version     = '%(prog)s {ver}'.format(ver = 'v%d.%d' %\
                            (VERSION, SUBVERSION)))

    args = parser.parse_args()

    if args.action in ['start_tx', 'start_tx_cw', 'start_tx_cont', 'start_rx']:
        if args.freq not in range(0, 40):
            print ("!!! Please specify the frequency index !!!")
            print (usage())
            exit()

    ser = serial.Serial(
        port        = args.port,
        baudrate    = 115200,
        parity      = serial.PARITY_NONE,
        stopbits    = serial.STOPBITS_ONE,
        bytesize    = serial.EIGHTBITS,
        timeout     = 0.2,
    )

    ser.close()

    ser.open()

    if ser.is_open is True:
        send_cmd(args, ser)
        recv_rsp(args, ser)
        ser.close()

if __name__ == "__main__":
   main()
