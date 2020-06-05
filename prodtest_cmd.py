#!/usr/bin/python

import argparse
import os
import os.path
import serial
import sys
import time
import threading

from array import *

VERSION     = '0'
SUBVERSION  = '6rc0'

HCI_PKT_INDICATOR_COMMAND           = '01'
HCI_PKT_INDICATOR_ACL_DATA          = '02'
HCI_PKT_INDICATOR_SYNCHRONOUS_DATA  = '03'
HCI_PKT_INDICATOR_EVENT             = '04'

VS_PKT_INDICATOR_COMMAND            = '41'  # char 'A'

HCI_EVTCODE_HCI_COMMAND_COMPLETE              = '0E'
HCI_EVTCODE_HCI_NUMBER_OF_COMPLETED_PACKETS   = '13'

HCI_OPCODE_HCI_RESET                = '0C03'
HCI_OPCODE_HCI_LE_RECEIVER_TEST     = '201D'
HCI_OPCODE_HCI_LE_TRANSMITTER_TEST  = '201E'
HCI_OPCODE_HCI_LE_TEST_END          = '201F'

HCI_OPCODE_HCI_VS_READ_VER          = 'FD01'
HCI_OPCODE_HCI_VS_REG_READ          = 'FD02'
HCI_OPCODE_HCI_VS_REG_WRITE         = 'FD03'


ACTION_LIST_ENTRY0                  = 0
ACTION_LIST_ENTRY1                  = 1
ACTION_LIST_ENTRY2                  = 2
FREQ_LIST_ENTRY0                    = 0
FREQ_LIST_ENTRY1                    = 1

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

curr_sweep_freq = -1
sweep_rf_on = False
start_freq  = -1
stop_freq   = -1

data_ready  = threading.Event()
 
 
def keyboard_poller():

    input("***********************************\r\n Press Enter to terminate the test \r\n***********************************\r\n")

    data_ready.set()


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
        '08' : 'Carrier Wave', # am propietary parameter value
        '09' : 'Continuous Modulated Signal', # am propietary parameter value
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
    # nothing to do for this command. A place holder here.
    return None

def HCI_Vs_Read_Ver_parser(args, rawdata):
    # nothing to do for this command. A place holder here.
    return None

def HCI_Vs_Reg_Read_parser(args, rawdata):

    HCI_VS_REG_READ_ADDR_OFFSET = 0

    ret = 'Address: 0x' + ''.join(format(x, '02X') for x in (rawdata[HCI_VS_REG_READ_ADDR_OFFSET:])[::-1])

    return ret

def HCI_Vs_Reg_Write_parser(args, rawdata):

    HCI_VS_REG_WRITE_ADDR_OFFSET = 0
    HCI_VS_REG_WRITE_VALUE_OFFSET = 4

    addr    = ''.join(format(x, '02X') for x in (rawdata[HCI_VS_REG_WRITE_ADDR_OFFSET:HCI_VS_REG_WRITE_VALUE_OFFSET])[::-1])
    val     = ''.join(format(x, '02X') for x in (rawdata[HCI_VS_REG_WRITE_VALUE_OFFSET:])[::-1])

    ret = 'Address: 0x'  + addr + ', Value: 0x' + val
    return ret

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

def HCI_Vs_Read_Ver_RetParam_parser(args, rawdata):

    HCI_VS_READ_VER_RETPARAM_STATUS_OFFSET = 0
    HCI_VS_READ_VER_RETPARAM_VER_OFFSET = 1

    status = ''.join('{:02X}'.format(rawdata[HCI_VS_READ_VER_RETPARAM_STATUS_OFFSET]))
    ver = rawdata[HCI_VS_READ_VER_RETPARAM_STATUS_OFFSET:].decode("ASCII")

    ret =   'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{}), '.format(status)
    ret +=  'Ver: ' + ver

    return ret

def HCI_Vs_Reg_Read_RetParam_parser(args, rawdata):

    HCI_VS_REG_READ_RETPARAM_STATUS_OFFSET = 0
    HCI_VS_REG_READ_RETPARAM_VALUE_OFFSET = 1

    status = ''.join('{:02X}'.format(rawdata[HCI_VS_REG_READ_RETPARAM_STATUS_OFFSET]))
    val = ''.join(format(x, '02X') for x in (rawdata[HCI_VS_REG_READ_RETPARAM_VALUE_OFFSET:])[::-1])

    ret =   'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{}), '.format(status)
    ret +=  'Value: 0x' + val

    return ret

def HCI_Vs_Reg_Write_RetParam_parser(args, rawdata):

    HCI_VS_REG_WRITE_RETPARAM_STATUS_OFFSET = 0

    status = ''.join('{:02X}'.format(rawdata[HCI_VS_REG_WRITE_RETPARAM_STATUS_OFFSET]))

    ret =   'Status: ' + dict_error_codes.get(status, "N/A") + ' (0x{}), '.format(status)

    return ret

# -------------------------------------------------------------------

# Name, command assembler, command parser, response parser
dict_opcodes = {
    HCI_OPCODE_HCI_RESET                : ('HCI_Reset',                 None, HCI_Reset_parser,                 HCI_Reset_Return_Parameters_parser),
    HCI_OPCODE_HCI_LE_RECEIVER_TEST     : ('HCI_LE_Receiver_Test',      None, HCI_LE_Receiver_Test_parser,      HCI_LE_Receiver_Test_Return_Parameters_parser),
    HCI_OPCODE_HCI_LE_TRANSMITTER_TEST  : ('HCI_LE_Transmitter_Test',   None, HCI_LE_Transmitter_Test_parser,   HCI_LE_Transmitter_Test_Return_Parameters_parser),
    HCI_OPCODE_HCI_LE_TEST_END          : ('HCI_LE_Test_End',           None, HCI_LE_Test_End_parser,           HCI_LE_Test_End_Return_Parameters_parser),
    HCI_OPCODE_HCI_VS_READ_VER          : ('HCI_VS_READ_VER',           None, HCI_Vs_Read_Ver_parser,           HCI_Vs_Read_Ver_RetParam_parser),
    HCI_OPCODE_HCI_VS_REG_READ          : ('HCI_VS_REG_READ',           None, HCI_Vs_Reg_Read_parser,           HCI_Vs_Reg_Read_RetParam_parser),
    HCI_OPCODE_HCI_VS_REG_WRITE         : ('HCI_VS_REG_WRITE',          None, HCI_Vs_Reg_Write_parser,          HCI_Vs_Reg_Write_RetParam_parser),
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

def HCI_Number_Of_Completed_Packets_parser(args, rawdata):

    EVENT_PARAM_NUM_OF_HANDLES_OFFSET = 0
    EVENT_PARAM_CONNECTION_HANDLE = 1
    EVENT_PARAM_HC_NUM_OF_COMPLETED_PACKETS = 3

    num_of_conns = ''.join('{:02X}'.format(rawdata[EVENT_PARAM_NUM_OF_HANDLES_OFFSET]))

    if args.log is True:
        ret =   '\tHCI_Number_Of_Completed_Packets\r\n'
        ret +=  '\t[Number of Handles] 0x{:02X}\r\n'.format(rawdata[EVENT_PARAM_NUM_OF_HANDLES_OFFSET])

    for idx in range(int(num_of_conns)):
        conn_handle = ''.join('{:02X}'.format(rawdata[idx * 2 + EVENT_PARAM_CONNECTION_HANDLE + 1])) + \
                    ''.join('{:02X}'.format(rawdata[idx * 2 + EVENT_PARAM_CONNECTION_HANDLE]))

        num_of_packets = ''.join('{:02X}'.format(rawdata[idx * 2 + EVENT_PARAM_HC_NUM_OF_COMPLETED_PACKETS + 1])) + \
                    ''.join('{:02X}'.format(rawdata[idx * 2 + EVENT_PARAM_HC_NUM_OF_COMPLETED_PACKETS]))

        if args.log is True:
            # ret =   '\tHCI_Number_Of_Completed_Packets\r\n'
            # ret +=  '\t[Number of Handles] 0x{:02X}\r\n'.format(conn_handle)
            ret +=  '\t[Connection Handle] 0x{}\r\n'.format(conn_handle)
            ret +=  '\t[HC Number of Completed Packets] 0x{}'.format(num_of_packets)
        else:
            ret = ''
    # else:
        # ret =   '\tNo parser available for Opcode 0x{}\r\n'.format(opcode)

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

    HCI_PKT_EVENT_EVENT_CODE_OFFSET         = 0
    HCI_PKT_EVENT_PARAM_TOTAL_LEN_OFFSET    = 1
    HCI_PKT_EVENT_EVENT_PARAM_OFFSET        = 2

    dict_hci_pkt_event_codes = {
        HCI_EVTCODE_HCI_COMMAND_COMPLETE            : ('HCI_Command_Complete',              HCI_Command_Complete_parser),
        HCI_EVTCODE_HCI_NUMBER_OF_COMPLETED_PACKETS : ('HCI_Number_Of_Completed_Packets',   HCI_Number_Of_Completed_Packets_parser),
    }

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

    cmd         = bytearray(b'\x01\x1E\x20\x03\x25')
    freq        = args.freq[FREQ_LIST_ENTRY0]

    if len(args.action) < 2:
        return None

    payload_int = int(args.action[ACTION_LIST_ENTRY1])

    if payload_int in range (0, 10) or payload_int == 255:
        # Append the payload index to cmd
        cmd.append(payload_int)
    else:
        return None

    if freq in range(0, 40):
        # Insert the frequency index to cmd[-2]
        cmd.insert(-2, freq)

        return cmd

    else:
        return None

def start_tx_cw_handler(args):

    if len(args.action) < 2:
        args.action.append(8)
    else:
        args.action[ACTION_LIST_ENTRY1] = 8

    return start_tx_handler(args)

def start_tx_cont_handler(args):

    args.action.append(9)

    return start_tx_handler(args)

def start_rx_handler(args):

    freq = args.freq[FREQ_LIST_ENTRY0]

    if freq in range(0, 40):
        cmd = bytearray(b'\x01\x1D\x20\x01')

        cmd.append(freq)

        return cmd

    else:
        return None

def stop_test_handler(args):

    return bytearray(b'\x01') + (bytearray.fromhex(HCI_OPCODE_HCI_LE_TEST_END))[::-1] + bytearray(b'\x00')

def sweep_test_channel_update(args):

    global curr_sweep_freq
    global start_freq
    global stop_freq

    args_freq_list_len = len(args.freq)

    if start_freq == -1 or stop_freq == -1:
        if args_freq_list_len == 2:
            start_freq  = int(args.freq[FREQ_LIST_ENTRY0])
            stop_freq   = int(args.freq[FREQ_LIST_ENTRY1])
        else:
            start_freq  = int(0)
            stop_freq   = int(39)

        curr_sweep_freq = start_freq
    else:
        curr_sweep_freq = curr_sweep_freq + 1

    if curr_sweep_freq == stop_freq + 1:
        curr_sweep_freq = start_freq

    args.freq[FREQ_LIST_ENTRY0] = curr_sweep_freq;

def start_tx_sweep_handler(args):

    sweep_test_channel_update(args)

    print ("start tx sweeping on channel\t{}".format(curr_sweep_freq))
    sys.stdout.flush()

    return start_tx_cw_handler(args)

def start_rx_sweep_handler(args):

    sweep_test_channel_update(args)

    print ("start tx sweeping on channel\t{}".format(curr_sweep_freq))
    sys.stdout.flush()

    return start_rx_handler(args)

def set_xtrim_handler(args):

    return bytearray(b'\x41\x4D\x31') + int(args.action[ACTION_LIST_ENTRY1]).to_bytes(2, byteorder='big')

def set_txpower_handler(args):

    return bytearray(b'\x41\x4D\x30') + int(args.action[ACTION_LIST_ENTRY1]).to_bytes(2, byteorder='big')

def read_version_handler(args):

    return bytearray.fromhex(HCI_PKT_INDICATOR_COMMAND) + (bytearray.fromhex(HCI_OPCODE_HCI_VS_READ_VER))[::-1] + bytearray(b'\x00')

def reg_read_handler(args):

    tmp = args.action[ACTION_LIST_ENTRY1].replace('0x', '')

    addr = (bytearray.fromhex(tmp.zfill(8)))[::-1]

    return bytearray.fromhex(HCI_PKT_INDICATOR_COMMAND) + (bytearray.fromhex(HCI_OPCODE_HCI_VS_REG_READ))[::-1] + bytes([len(addr)]) + addr


def reg_write_handler(args):

    tmp = args.action[ACTION_LIST_ENTRY1].replace('0x', '')

    addr = (bytearray.fromhex(tmp.zfill(8)))[::-1]

    tmp = args.action[ACTION_LIST_ENTRY2].replace('0x', '')

    val = bytearray.fromhex(tmp.zfill(8))[::-1]

    return bytearray.fromhex(HCI_PKT_INDICATOR_COMMAND) + (bytearray.fromhex(HCI_OPCODE_HCI_VS_REG_WRITE))[::-1] + bytes([len(addr) + len(val)]) + addr + val

# ----------------------------------------

def send_cmd(args, ser):

    dict_actions = {
        'reset'         : ('Reset DUT',                             reset_handler),
        'start_tx'      : ('Start TX Test',                         start_tx_handler),
        'start_tx_cw'   : ('Start TX Carrier Wave',                 start_tx_cw_handler),
        'start_tx_cont' : ('Start TX Continuous Modulated Signal',  start_tx_cont_handler),
        'start_tx_sweep': (None,                                    start_tx_sweep_handler),
        'start_rx'      : ('Start RX Test',                         start_rx_handler),
        'start_rx_sweep': (None,                                    start_rx_sweep_handler),
        'stop_test'     : ('Stop Test',                             stop_test_handler),
        'set_xtrim'     : ('Set 32MHz Trim Value',                  set_xtrim_handler),
        'set_txpower'   : ('Set Tx Power',                          set_txpower_handler),
        'read_ver'      : ('Read version',                          read_version_handler),
        'regr'          : ('Register read',                         reg_read_handler),
        'regw'          : ('Register Write',                        reg_write_handler),
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
                    print (parser(args, cmd[HCI_PKT_PAYLOAD_OFFSET:]))

            else:
                if description is not None:
                    print ('{}'.format(description))

            ser.write(cmd)

        else:
            print ('!!! Error !!! Please check the parameters')

    else:
        print ("!!! Error !!! {} not supported".format(args.action))

def recv_rsp(args, ser):

    HCI_PKT_INDICATOR_OFFSET                = 0
    HCI_PKT_PAYLOAD_OFFSET                  = 1
    HCI_PKT_EVENT_PARAM_TOTAL_LEN_OFFSET    = 2

    res = ser.read(2000)

    cur_idx = 0

    if len(res) <= 0:
        print("no response received")
    else:
        if args.log is True:
            print ('>>', ' '.join('0x{:02X}'.format(x) for x in res))

        while cur_idx < len(res) - 1:

            packet_length = HCI_PKT_EVENT_PARAM_TOTAL_LEN_OFFSET + 1 + int(''.join('{:02X}'.format(res[cur_idx + HCI_PKT_EVENT_PARAM_TOTAL_LEN_OFFSET])))

            pkt_type = ''.join('{:02X}'.format(res[HCI_PKT_INDICATOR_OFFSET]))

            (assembler, parser) = dict_hci_pkt_types.get(pkt_type, (None, None))

            if parser is not None:
                ret = parser(args, res[cur_idx + HCI_PKT_PAYLOAD_OFFSET:])

            else:
                ret = 'No parser available for HCI Packet Type 0x{}'.format(pkt_type)

            print (ret)

            cur_idx = cur_idx + packet_length



def usage(name=None):                                                            
    return '''
        Reset DUT\t\t\t\t: prodtest_cmd.py -p <COM> -a reset
        Stop Test\t\t\t\t: prodtest_cmd.py -p <COM> -a stop_test
        Start TX Test\t\t\t\t: prodtest_cmd.py -p <COM> -a start_tx <PAYLOAD>[0(PRBS9), 1(11110000), 2(10101010), 3(PRBS15), 4(11111111), 5(00000000), 6(00001111), 7(01010101), 8(Carrier Wave), 9(Continuous Modulated Signal)] -f <FREQ>
        Start TX Carrier Wave\t\t\t: prodtest_cmd.py -p <COM> -a start_tx_cw -f <FREQ>
        Start TX Continuous Modulated Signal\t: prodtest_cmd.py -p <COM> -a start_tx_cont -f <FREQ>
        Start TX Sweep\t\t\t\t: prodtest_cmd.py -p <COM> -a start_tx_sweep -f <START FREQ> <STOP FREQ> -t <TIMESPAN>
        Start RX test\t\t\t\t: prodtest_cmd.py -p <COM> -a start_rx -f <FREQ>
        Start RX Sweep\t\t\t\t: prodtest_cmd.py -p <COM> -a start_rx_sweep -f <START FREQ> <STOP FREQ> -t <TIMESPAN>
        Set XTrim Value\t\t\t\t: prodtest_cmd.py -p <COM> -a set_xtrim <VALUE in decimal>
        Set Tx Power\t\t\t\t: prodtest_cmd.py -p <COM> -a set_txpower <VALUE>[3(-20dBm), 4(-10dBm), 5(-5dBm), 8(0dBm), 15(4dBm)]
        Read version\t\t\t\t: prodtest_cmd.py -p <COM> -a read_ver
        Register read\t\t\t\t: prodtest_cmd.py -p <COM> -a regr <ADDR in hex>
        Register write\t\t\t\t: prodtest_cmd.py -p <COM> -a regw <ADDR in hex> <VALUE in hex>
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
                        nargs       = '*',
                        help        = 'Channle Index(0 to 39) to be tested.',
                        )

    parser.add_argument('-t', '--timespan',
                        dest        = 'timespan',
                        required    = False,
                        type        = int,
                        default     = 100,
                        help        = 'duration(ms) in a channel in sweeping tests',
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
                        version     = '%(prog)s {ver}'.format(ver = 'v%s.%s' %\
                            (VERSION, SUBVERSION)))

    args = parser.parse_args()

    single_action = True

    if args.action[ACTION_LIST_ENTRY0] in ['start_tx_sweep', 'start_rx_sweep']:
        single_action = False

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

        if single_action is True:
            send_cmd(args, ser)
            recv_rsp(args, ser)
        else:
            poller = threading.Thread(target=keyboard_poller)
            poller.start()

            loop = True

            user_action_cache = args.action[ACTION_LIST_ENTRY0]

            while loop:
                args.action[ACTION_LIST_ENTRY0] = user_action_cache
                send_cmd(args, ser)
                recv_rsp(args, ser)
                time.sleep(args.timespan / 1000)

                args.action[ACTION_LIST_ENTRY0] = 'reset'

                send_cmd(args, ser)
                recv_rsp(args, ser)

                if data_ready.isSet():
                    loop = False
                    data_ready.clear()



    ser.close()

if __name__ == "__main__":
    main()
    exit()
