#!/usr/bin/env python3
import logging
import re
import telnetlib as tn
import persistentdatatools as pdt
import ipaddresstools as ipv4
__author__ = 'Benjamin P. Trachtenberg'
__copyright__ = "Copyright (c) 2017, Benjamin P. Trachtenberg"
__credits__ = None
__license__ = 'The MIT License (MIT)'
__status__ = 'dev'
__version_info__ = (1, 2, 0)
__version__ = '.'.join(map(str, __version_info__))
__maintainer__ = 'Benjamin P. Trachtenberg'
__email__ = 'e_ben_75-python@yahoo.com'
LOGGER = logging.getLogger(__name__)


class CiscoTelnetClass:
    """
    Class to telnet and pull info from a Cisco device
    """
    def __init__(self):
        LOGGER.debug('Initializing class {class_type}'.format(class_type=type(self)))
        self.prompt_list = [re.compile(b'username:', flags=re.IGNORECASE),
                            re.compile(b'login:', flags=re.IGNORECASE)]
        self.password_prompt_list = [re.compile(b'enter safeword password:', flags=re.IGNORECASE),
                                     re.compile(b'password:', flags=re.IGNORECASE)]
        self.device_name_prompt_list = [re.compile(b'([a-z]|[0-9]|-|:|/)*#$', flags=re.IGNORECASE)]
        self.vrf_name_list = None
        self.objSession = tn.Telnet()
        self.pull_lists_dict = dict()

    def open_connection(self):
        """
        Method to login to a Cisco device
        :return: None
        """
        LOGGER.debug('Starting Method open_connection in {class_type}'.format(class_type=type(self)))
        self.__login_info_set()
        self.objSession.open(self.device_ip)
        tuple_rcvd = self.objSession.expect(self.prompt_list, timeout=2)
        self.log_expect_data('open_connection', 'username', tuple_rcvd)
        self.__write_to_ascii(self.user_name)
        tuple_rcvd = self.objSession.expect(self.password_prompt_list, timeout=2)
        self.log_expect_data('open_connection', 'password', tuple_rcvd)
        self.__write_to_ascii(self.user_password)
        tuple_rcvd = self.objSession.expect(self.device_name_prompt_list, timeout=2)
        self.log_expect_data('open_connection', 'device_name', tuple_rcvd)
        self.__write_to_ascii('terminal length 0')
        tuple_rcvd = self.objSession.expect(self.device_name_prompt_list, timeout=2)
        self.log_expect_data('open_connection', 'device_name', tuple_rcvd)

    def log_expect_data(self, method_name, description, tuple_data):
        """
        Method to log expect data
        :param method_name: The name of the method loggin
        :param description: Description of what it is looking for
        :param tuple_data: data received from the expect statment
        :return:
            None

        """
        LOGGER.debug('Method {method_name} in {class_type} expect '
                     'for {description} expect result {result} matched {matched}'.format(method_name=method_name,
                                                                                         class_type=type(self),
                                                                                         description=description,
                                                                                         result=tuple_data[0],
                                                                                         matched=tuple_data[1]))

    def __write_to_ascii(self, command):
        """
        Method needed to encode a command in ascii, includes line break
        :param command: The command to run
        :return:

        """
        LOGGER.debug('Starting Method __write_to_ascii in {class_type}'.format(class_type=type(self)))
        self.objSession.write((command + "\n").encode('ascii'))

    def __decode_bytes_to_ascii(self, orig_list_byte_encoded):
        """
        Method needed to decode the returned list to ascii
        :param orig_list_byte_encoded: List to decode
        :return: A ASCII encoded list

        """
        temp_list = list()
        for line in orig_list_byte_encoded:
            temp_list.append(line.decode('ascii'))

        return temp_list

    def __ios_run_pull(self):
        """
        Method to take a show running-config from an IOS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __ios_run_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show running-config')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_run_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __ios_cef_pull(self, vrf_name=None):
        """
        Method to take a show ip cef from an IOS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __ios_cef_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show ip cef vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show ip cef')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_cef_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __ios_mroute_pull(self, vrf_name=None):
        """
        Method to take a show ip mroute from an IOS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __ios_mroute_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show ip mroute vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show ip mroute')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_mroute_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __ios_bgp_pull(self, vrf_name=None):
        """
        Method to take a show ip bgp from an IOS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __ios_bgp_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show ip bgp vpnv4 vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show ip bgp')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_bgp_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __ios_mac_pull(self):
        """
        Method to take a show mac-address-table dynamic from an IOS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __ios_mac_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show mac-address-table dynamic')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_mac_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __ios_arp_pull(self, vrf_name=None):
        """
        Method to take a show ip arp from an IOS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __ios_arp_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show ip arp vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show ip arp')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_arp_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __ios_vrfs_pull(self):
        """
        Method to retreive VRF's from a IOS device
        :return:  returns a list
        """
        LOGGER.debug('Starting Method __ios_vrfs_pull in {class_type}'.format(class_type=type(self)))
        temp_vrf_list = list()
        self.__write_to_ascii('show vrf')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__ios_vrfs_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        for line in info_list:
            line_split = line.split()
            if len(line_split) == 4:
                temp_vrf_list.append(line_split[0].decode('ascii'))
        return temp_vrf_list

    def __nxos_run_pull(self):
        """
        Method to take a show running-config from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __nxos_run_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show running-config')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__nxos_run_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __nxos_cef_pull(self):
        """
        Method to take a show forwarding ipv4 route from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __nxos_cef_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show forwarding ipv4 route')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__nxos_cef_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __nxos_mroute_pull(self):
        """
        Method to take a show ip mroute from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __nxos_mroute_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show ip mroute')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__nxos_mroute_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __nxos_bgp_pull(self):
        """
        Method to take a show ip bgp from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __nxos_bgp_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show ip bgp')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__nxos_bgp_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __nxos_mac_pull(self):
        """
        Method to take a show mac address-table dynamic from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __nxos_mac_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show mac address-table dynamic')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__nxos_mac_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __nxos_arp_pull(self):
        """
        Method to take a show ip arp from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __nxos_arp_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show ip arp')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__nxos_arp_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __xr_run_pull(self):
        """
        Method to take a show running-config from an NX-OS device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __xr_run_pull in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('show running-config')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__xr_run_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __xr_cef_pull(self, vrf_name=None):
        """
        Method to take a show cef from an IOS-XR device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __xr_cef_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show cef vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show cef')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__xr_cef_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __xr_mroute_pull(self, vrf_name=None):
        """
        Method to take a show mrib route from an IOS-XR device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __xr_mroute_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show mrib vrf {vrf_name} route'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show mrib route')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__xr_mroute_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __xr_bgp_pull(self, vrf_name=None):
        """
        Method to take a show bgp from an IOS-XR device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __xr_bgp_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show bgp vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show bgp')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__xr_bgp_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __xr_arp_pull(self, vrf_name=None):
        """
        Method to take a show arp from an IOS-XR device, and turn it into a list
        :return: returns a list
        """
        LOGGER.debug('Starting Method __xr_arp_pull in {class_type}'.format(class_type=type(self)))
        if vrf_name:
            self.__write_to_ascii('show arp vrf {vrf_name}'.format(vrf_name=vrf_name))
        else:
            self.__write_to_ascii('show arp')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__xr_arp_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        return info_list

    def __xr_vrfs_pull(self):
        """
        Method to retreive VRF's from a XR device
        :return:  returns a list
        """
        LOGGER.debug('Starting Method __xr_vrfs_pull in {class_type}'.format(class_type=type(self)))
        temp_vrf_list = list()
        self.__write_to_ascii('show vrf all')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=15)
        self.log_expect_data('__xr_vrfs_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()
        for line in info_list:
            line_split = line.split()
            if len(line_split) == 2:
                temp_vrf_list.append(line_split[0].decode('ascii'))
        return temp_vrf_list

    def __login_info_set(self):
        """
        Method to set the login info
        :return:
        """
        LOGGER.debug('Starting Method __login_info_set in {class_type}'.format(class_type=type(self)))
        self.user_name = input("Username: ")
        self.user_password = input("Password: ")
        self.device_ip = input("Device IP: ")

    def ios_pull(self):
        """
        Method to run all pull information for IOS
        :return: A dictionary of lists
        """
        LOGGER.debug('Starting Method ios_pull in {class_type}'.format(class_type=type(self)))
        temp_vrf_dict = dict()
        self.pull_lists_dict['VRF'] = temp_vrf_dict
        self.vrf_name_list = self.__ios_vrfs_pull()

        self.pull_lists_dict['CEF'] = self.__decode_bytes_to_ascii(self.__ios_cef_pull())
        self.pull_lists_dict['MROUTE'] = self.__decode_bytes_to_ascii(self.__ios_mroute_pull())
        self.pull_lists_dict['BGP'] = self.__decode_bytes_to_ascii(self.__ios_bgp_pull())
        self.pull_lists_dict['MAC'] = self.__decode_bytes_to_ascii(self.__ios_mac_pull())
        self.pull_lists_dict['ARP'] = self.__decode_bytes_to_ascii(self.__ios_arp_pull())
        self.pull_lists_dict['RUN'] = self.__decode_bytes_to_ascii(self.__ios_run_pull())

        if self.vrf_name_list:
            for vrf_name in self.vrf_name_list:
                self.pull_lists_dict['VRF'].update({vrf_name: {
                    'CEF': self.__decode_bytes_to_ascii(self.__ios_cef_pull(vrf_name)),
                    'MROUTE':  self.__decode_bytes_to_ascii(self.__ios_mroute_pull(vrf_name)),
                    'BGP': self.__decode_bytes_to_ascii(self.__ios_bgp_pull(vrf_name)),
                    'ARP': self.__decode_bytes_to_ascii(self.__ios_arp_pull(vrf_name)),
                }})

        return self.pull_lists_dict

    def nxos_pull(self):
        """
        Method to run all pull information for NX-OS
        :return: A dictionary of lists
        """
        LOGGER.debug('Starting Method nxos_pull in {class_type}'.format(class_type=type(self)))
        self.pull_lists_dict['CEF'] = self.__decode_bytes_to_ascii(self.__nxos_cef_pull())
        self.pull_lists_dict['MROUTE'] = self.__decode_bytes_to_ascii(self.__nxos_mroute_pull())
        self.pull_lists_dict['BGP'] = self.__decode_bytes_to_ascii(self.__nxos_bgp_pull())
        self.pull_lists_dict['MAC'] = self.__decode_bytes_to_ascii(self.__nxos_mac_pull())
        self.pull_lists_dict['ARP'] = self.__decode_bytes_to_ascii(self.__nxos_arp_pull())
        self.pull_lists_dict['RUN'] = self.__decode_bytes_to_ascii(self.__nxos_run_pull())
        return self.pull_lists_dict

    def xr_pull(self):
        """
        Method to run all pull information for IOS-XR
        :return: A dictionary of lists
        """
        LOGGER.debug('Starting Method xr_pull in {class_type}'.format(class_type=type(self)))
        temp_vrf_dict = dict()
        self.pull_lists_dict['VRF'] = temp_vrf_dict
        self.vrf_name_list = self.__xr_vrfs_pull()

        self.pull_lists_dict['CEF'] = self.__decode_bytes_to_ascii(self.__xr_cef_pull())
        self.pull_lists_dict['MROUTE'] = self.__decode_bytes_to_ascii(self.__xr_mroute_pull())
        self.pull_lists_dict['BGP'] = self.__decode_bytes_to_ascii(self.__xr_bgp_pull())
        self.pull_lists_dict['ARP'] = self.__decode_bytes_to_ascii(self.__xr_arp_pull())
        self.pull_lists_dict['RUN'] = self.__decode_bytes_to_ascii(self.__xr_run_pull())

        if self.vrf_name_list:
            for vrf_name in self.vrf_name_list:
                self.pull_lists_dict['VRF'].update({vrf_name: {
                    'CEF': self.__decode_bytes_to_ascii(self.__xr_cef_pull(vrf_name)),
                    'MROUTE':  self.__decode_bytes_to_ascii(self.__xr_mroute_pull(vrf_name)),
                    'BGP': self.__decode_bytes_to_ascii(self.__xr_bgp_pull(vrf_name)),
                    'ARP': self.__decode_bytes_to_ascii(self.__xr_arp_pull(vrf_name)),
                }})

        return self.pull_lists_dict

    def check_os_type_and_pull(self):
        """
        Method to figure out OS, and pull the appropriate info
        :return:
            A Dictionary of lists with the following keys
                CEF,
                MROUTE,
                BGP,
                MAC,
                ARP,
                RUN

        """
        LOGGER.debug('Starting Method check_os_type in {class_type}'.format(class_type=type(self)))
        ios_xr = re.compile(b'^Cisco IOS XR Software', flags=re.IGNORECASE)
        ios = re.compile(b'^Cisco IOS Software', flags=re.IGNORECASE)
        nxos = re.compile(b'^Cisco Nexus Operating System', flags=re.IGNORECASE)
        ios_xe = re.compile(b'^Cisco IOS-XE Software', flags=re.IGNORECASE)
        use_pull_version = None
        dcit_return = None
        self.__write_to_ascii('show version')
        info_tuple = self.objSession.expect(self.device_name_prompt_list, timeout=2)
        self.log_expect_data('check_os_type_and_pull', 'device_name', info_tuple)
        info_list = info_tuple[2].splitlines()

        for line in info_list:
            if ios_xr.match(line):
                use_pull_version = 'IOS-XR'
                break
            elif ios.match(line):
                use_pull_version = 'IOS'
                break
            elif nxos.match(line):
                use_pull_version = 'NX-OS'
                break
            elif ios_xe.match(line):
                use_pull_version = 'IOS'
                break

        if use_pull_version == 'IOS-XR':
            dcit_return = self.xr_pull()
        elif use_pull_version == 'IOS':
            dcit_return = self.ios_pull()
        elif use_pull_version == 'NX-OS':
            dcit_return = self.nxos_pull()

        return dcit_return

    def close_connection(self):
        """
        Method to disconnect your session
        :return:
        """
        LOGGER.debug('Starting Method close_connection in {class_type}'.format(class_type=type(self)))
        self.__write_to_ascii('exit')
        self.objSession.close()


class CiscoInfoNormalizer:
    """
    Class to normalize data between Cisco IOS, IOS-XR, and NX-OS
    """
    regex_ucast_ip_mask = re.compile("^((22[0-3])|(2[0-1][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))/((3[0-2])|([1-2]?[0-9]))")
    regex_ucast_ip = re.compile("^((22[0-3])|(2[0-1][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))\.((25[0-5])|(2[0-4][0-9])|(1[0-9][0-9])|([1-9]?[0-9]))")
    regex_mac = re.compile("^[0-9|a-f][0-9|a-f][0-9|a-f][0-9|a-f]\.[0-9|a-f][0-9|a-f][0-9|a-f][0-9|a-f]\.[0-9|a-f][0-9|a-f][0-9|a-f][0-9|a-f]$")

    def __init__(self, INPUT_DIR):
        """
        :param INPUT_DIR: The directory of input
        :return:
        """
        LOGGER.debug('Initializing class {class_type}'.format(class_type=type(self)))
        self.INPUT_DIR = INPUT_DIR

    def ios_cef_to_dict(self, cef_file_name=None):
        """
        Method to take a show ip cef from an IOS device, and turn it into a dictionary
        :param cef_file_name: The text file of the information
        :return: returns a dictionary including this info ROUTE, NEXTHOP, and possibly INTERFACE
        """
        LOGGER.debug('Starting Method ios_cef_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        cef_table_list = pdt.file_to_list(cef_file_name, self.INPUT_DIR)
        for cef_line in cef_table_list:
            cef_line = ' '.join(cef_line.split())
            cef_line_split = cef_line.split()
            try:
                if ipv4.ucast_ip_mask(cef_line_split[0], False):
                    if len(cef_line_split) == 3:
                        temp_dict[dict_key] = {'ROUTE': cef_line_split[0], 'NEXTHOP': cef_line_split[1],
                                               'INTERFACE': cef_line_split[2]}
                        dict_key += 1
                    elif len(cef_line_split) == 2:
                        temp_dict[dict_key] = {'ROUTE': cef_line_split[0], 'NEXTHOP': cef_line_split[1]}
                        dict_key += 1
                    else:
                        pass

            except Exception as e:
                LOGGER.warning('Method ios_cef_to_dict in {class_type} error {e}'.format(class_type=type(self), e=e))

        return temp_dict

    def ios_sho_ip_bgp_to_dict(self, bgp_file_name=None):
        """
        Method to take a show ip bgp from an IOS device, and turn it into a dictionary
        :param bgp_file_name: The text file of the information
        :return: returns a dictionary including this info NETWORK
        """
        LOGGER.debug('Starting Method ios_sho_ip_bgp_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        final_set = set()
        bgp_list = pdt.file_to_list(bgp_file_name, self.INPUT_DIR)
        for bgp_line in bgp_list:
            bgp_line = ''.join(bgp_line.split('l'))
            bgp_line = ''.join(bgp_line.split('r'))
            bgp_line = ''.join(bgp_line.split('e'))
            bgp_line = ''.join(bgp_line.split('s'))
            bgp_line = ''.join(bgp_line.split('i'))
            bgp_line = ''.join(bgp_line.split('*'))
            bgp_line = ''.join(bgp_line.split('>'))
            bgp_line = ' '.join(bgp_line.split())
            bgp_line_split = bgp_line.split()
            if re.match(self.regex_ucast_ip_mask, bgp_line):
                final_set.add('%s,%s' % (bgp_line_split[0], bgp_line_split[1]))
            elif re.match(self.regex_ucast_ip, bgp_line):
                final_set.add('%s,%s' % (bgp_line_split[0], bgp_line_split[1]))
        for final_set_line in final_set:
            final_set_line_split = final_set_line.split(',')
            temp_dict[dict_key] = {'NETWORK': final_set_line_split[0], 'NEXTHOP': final_set_line_split[1]}
            dict_key += 1
        return temp_dict

    def ios_mroute_to_dict(self, mroute_file_name=None):
        """
        Method to take a show ip mroute from an IOS device, and turn it into a dictionary
        :param mroute_file_name: The text file of the information
        :return: returns a dictionary including this info SOURCE, and GROUP
        """
        LOGGER.debug('Starting Method ios_mroute_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        final_set = set()
        mroute_list = pdt.file_to_list(mroute_file_name, self.INPUT_DIR)
        for mroute_list_line in mroute_list:
            mroute_list_line = ''.join(mroute_list_line.split('*'))
            mroute_list_line = ''.join(mroute_list_line.split('>'))
            mroute_list_line = ''.join(mroute_list_line.split('('))
            mroute_list_line = ''.join(mroute_list_line.split(')'))
            mroute_list_line = ''.join(mroute_list_line.split(','))
            mroute_list_line = ' '.join(mroute_list_line.split())
            if re.match(self.regex_ucast_ip_mask, mroute_list_line):
                mroute_list_line_split = mroute_list_line.split()
                final_set.add('%s,%s' % (mroute_list_line_split[0], mroute_list_line_split[1]))
            elif re.match(self.regex_ucast_ip, mroute_list_line):
                mroute_list_line_split = mroute_list_line.split()
                final_set.add('%s/32,%s' % (mroute_list_line_split[0], mroute_list_line_split[1]))
        for final_set_line in final_set:
            final_set_line_split = final_set_line.split(',')
            temp_dict[dict_key] = {'SOURCE': final_set_line_split[0], 'GROUP': final_set_line_split[1]}
            dict_key += 1
        return temp_dict

    def ios_mac_addr_to_dict(self, mac_addr_file_name=None):
        """

        :param mac_addr_file_name: The text file of the information
        :return: returns a dictionary including this info VLAN, MAC, and INTERFACE
        """
        LOGGER.debug('Starting Method ios_mac_addr_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        mac_addr_list = pdt.file_to_list(mac_addr_file_name, self.INPUT_DIR)
        for mac_addr_list_line in mac_addr_list:
            mac_addr_list_line = ''.join(mac_addr_list_line.split('*'))
            mac_addr_list_line = ' '.join(mac_addr_list_line.split())
            mac_addr_list_line_split = mac_addr_list_line.split()
            if len(mac_addr_list_line_split) == 6:
                if re.match(self.regex_mac, mac_addr_list_line_split[1]):
                    temp_dict[dict_key] = {'VLAN': mac_addr_list_line_split[0], 'MAC': mac_addr_list_line_split[1],
                                           'INTERFACE': mac_addr_list_line_split[5]}
                    dict_key += 1
        return temp_dict

    def ios_ip_arp_to_dict(self, ip_arp_file_name=None):
        """
        Method to take a show ip arp from an IOS device, and turn it into a dictionary
        :param ip_arp_file_name: The text file of the information
        :return: returns a dictionary including this info IP, MAC, and INTERFACE
        """
        LOGGER.debug('Starting Method ios_ip_arp_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        ip_arp_list = pdt.file_to_list(ip_arp_file_name, self.INPUT_DIR)
        for ip_arp_list_line in ip_arp_list:
            ip_arp_list_line = ' '.join(ip_arp_list_line.split())
            ip_arp_list_line_split = ip_arp_list_line.split()
            if len(ip_arp_list_line_split) == 6:
                if re.match(self.regex_ucast_ip, ip_arp_list_line_split[1]):
                    temp_dict[dict_key] = {'IP': ip_arp_list_line_split[1], 'MAC': ip_arp_list_line_split[3],
                                           'INTERFACE': ip_arp_list_line_split[5]}
                    dict_key += 1
        return temp_dict

    def nxos_sho_ip_bgp_to_dict(self, bgp_file_name=None):
        """
        Method to take a show ip bgp from an NX-OS device, and turn it into a dictionary
        :param bgp_file_name: The text file of the information
        :return: returns a dictionary including this info NETWORK
        """
        LOGGER.debug('Starting Method nxos_sho_ip_bgp_to_dict in {class_type}'.format(class_type=type(self)))
        return self.ios_sho_ip_bgp_to_dict(bgp_file_name)

    def nxos_cef_to_dict(self, cef_file_name=None):
        """
        Method to take a show forwarding ipv4 route from an NX-OS device, and turn it into a dictionary
        :param cef_file_name: The text file of the information
        :return: returns a dictionary including this info ROUTE, NEXTHOP, and possibly INTERFACE
        """
        LOGGER.debug('Starting Method nxos_cef_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        final_set = set()
        cef_table_list = pdt.file_to_list(cef_file_name, self.INPUT_DIR)
        for cef_table_list_line in cef_table_list:
            cef_table_list_line = ''.join(cef_table_list_line.split('*'))
            cef_table_list_line = ' '.join(cef_table_list_line.split())
            try:
                final_set.add(cef_table_list_line)
            except Exception as e:
                LOGGER.warning('Method nxos_cef_to_dict in {class_type} error {e}'.format(class_type=type(self), e=e))

        for final_set_line in final_set:
            final_set_line = final_set_line.split()
            try:
                if ipv4.ucast_ip_mask(final_set_line[0], False):
                    if len(final_set_line) == 3:
                        temp_dict[dict_key] = {'ROUTE': final_set_line[0], 'NEXTHOP': final_set_line[1],
                                               'INTERFACE': final_set_line[2]}
                        dict_key += 1
                    elif len(final_set_line) == 2:
                        temp_dict[dict_key] = {'ROUTE': final_set_line[0], 'NEXTHOP': final_set_line[1]}
                        dict_key += 1
                    else:
                        pass

            except Exception as e:
                LOGGER.warning('Method nxos_cef_to_dict in {class_type} error {e}'.format(class_type=type(self), e=e))

        return temp_dict

    def nxos_mroute_to_dict(self, mroute_file_name=None):
        """
        Not fully baked
        :param mroute_file_name:
        :return:
        """
        LOGGER.debug('Starting Method nxos_mroute_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        final_set = set()
        mroute_list = pdt.file_to_list(mroute_file_name, self.INPUT_DIR)
        for mroute_list_line in mroute_list:
            mroute_list_line = ''.join(mroute_list_line.split('*'))
            mroute_list_line = ''.join(mroute_list_line.split('>'))
            mroute_list_line = ''.join(mroute_list_line.split('('))
            mroute_list_line = ''.join(mroute_list_line.split(')'))
            mroute_list_line = ''.join(mroute_list_line.split(','))
            mroute_list_line = ' '.join(mroute_list_line.split())
            if re.match(self.regex_ucast_ip_mask, mroute_list_line):
                mroute_list_line_split = mroute_list_line.split()
                final_set.add('%s,%s' % (mroute_list_line_split[0], mroute_list_line_split[1]))
            elif re.match(self.regex_ucast_ip, mroute_list_line):
                mroute_list_line_split = mroute_list_line.split()
                final_set.add('%s/32,%s' % (mroute_list_line_split[0], mroute_list_line_split[1]))
        for final_set_line in final_set:
            final_set_line_split = final_set_line.split(',')
            temp_dict[dict_key] = {'SOURCE': final_set_line_split[0], 'GROUP': final_set_line_split[1]}
            dict_key += 1
        return temp_dict

    def nxos_mac_addr_to_dict(self, mac_addr_file_name=None):
        """
        Method to take a show mac address-table dynamic from an NX-OS device, and turn it into a dictionary
        :param mac_addr_file_name: The text file of the information
        :return: returns a dictionary including this info VLAN, MAC, and INTERFACE
        """
        LOGGER.debug('Starting Method nxos_mac_addr_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        mac_addr_list = pdt.file_to_list(mac_addr_file_name, self.INPUT_DIR)
        for mac_addr_list_line in mac_addr_list:
            mac_addr_list_line = ''.join(mac_addr_list_line.split('*'))
            mac_addr_list_line = ' '.join(mac_addr_list_line.split())
            mac_addr_list_line_split = mac_addr_list_line.split()
            if len(mac_addr_list_line_split) == 7:
                if re.match(self.regex_mac, mac_addr_list_line_split[1]):
                    temp_dict[dict_key] = {'VLAN': mac_addr_list_line_split[0], 'MAC': mac_addr_list_line_split[1],
                                           'INTERFACE': mac_addr_list_line_split[6]}
                    dict_key += 1
        return temp_dict

    def nxo_ip_arp_to_dict(self, ip_arp_file_name=None):
        """
        Method to take a show ip arp from an NX-OS device, and turn it into a dictionary
        :param ip_arp_file_name: The text file of the information
        :return: returns a dictionary including this info IP, MAC, and INTERFACE
        """
        LOGGER.debug('Starting Method nxo_ip_arp_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        ip_arp_list = pdt.file_to_list(ip_arp_file_name, self.INPUT_DIR)
        for ip_arp_list_line in ip_arp_list:
            ip_arp_list_line = ' '.join(ip_arp_list_line.split())
            ip_arp_list_line_split = ip_arp_list_line.split()
            if len(ip_arp_list_line_split) == 4:
                if re.match(self.regex_ucast_ip, ip_arp_list_line_split[0]):
                    temp_dict[dict_key] = {'IP': ip_arp_list_line_split[0], 'MAC': ip_arp_list_line_split[2],
                                           'INTERFACE': ip_arp_list_line_split[3]}
                    dict_key += 1
        return temp_dict

    def xr_sho_ip_bgp_to_dict(self, bgp_file_name=None):
        """
        Method to take a show ip bgp from an IOS-XR device, and turn it into a dictionary
        :param bgp_file_name: The text file of the information
        :return: returns a dictionary including this info NETWORK
        """
        LOGGER.debug('Starting Method xr_sho_ip_bgp_to_dict in {class_type}'.format(class_type=type(self)))
        return self.ios_sho_ip_bgp_to_dict(bgp_file_name)

    def xr_cef_to_dict(self, cef_file_name=None):
        """
        Method to take a show cef from an IOS-XR device, and turn it into a dictionary
        :param cef_file_name: The text file of the information
        :return: returns a dictionary including this info ROUTE, NEXTHOP, and possibly INTERFACE
        """
        LOGGER.debug('Starting Method xr_cef_to_dict in {class_type}'.format(class_type=type(self)))
        return self.ios_cef_to_dict(cef_file_name)

    def xr_mroute_to_dict(self, mroute_file_name=None):
        """
        Method to take a show mrib route from an IOS-XR device, and turn it into a dictionary
        :param mroute_file_name: The text file of the information
        :return: returns a dictionary including this info SOURCE, and GROUP
        """
        LOGGER.debug('Starting Method xr_mroute_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        final_set = set()
        mroute_list = pdt.file_to_list(mroute_file_name, self.INPUT_DIR)
        for mroute_list_line in mroute_list:
            mroute_list_line = ''.join(mroute_list_line.split('*'))
            mroute_list_line = ''.join(mroute_list_line.split('>'))
            mroute_list_line = ''.join(mroute_list_line.split('('))
            mroute_list_line = ''.join(mroute_list_line.split(')'))
            mroute_list_line = ' '.join(mroute_list_line.split(','))
            mroute_list_line = ' '.join(mroute_list_line.split())
            if re.match(self.regex_ucast_ip_mask, mroute_list_line):
                mroute_list_line_split = mroute_list_line.split()
                final_set.add('%s,%s' % (mroute_list_line_split[0], mroute_list_line_split[1]))
            elif re.match(self.regex_ucast_ip, mroute_list_line):
                mroute_list_line_split = mroute_list_line.split()
                final_set.add('%s/32,%s' % (mroute_list_line_split[0], mroute_list_line_split[1]))
        for final_set_line in final_set:
            final_set_line_split = final_set_line.split(',')
            temp_dict[dict_key] = {'SOURCE': final_set_line_split[0], 'GROUP': final_set_line_split[1]}
            dict_key += 1
        return temp_dict

    def xr_ip_arp_to_dict(self, ip_arp_file_name=None):
        """
        Method to take a show arp from an IOS-XR device, and turn it into a dictionary
        :param ip_arp_file_name: The text file of the information
        :return: returns a dictionary including this info IP, MAC, and INTERFACE
        """
        LOGGER.debug('Starting Method xr_ip_arp_to_dict in {class_type}'.format(class_type=type(self)))
        temp_dict = dict()
        dict_key = 1
        ip_arp_list = pdt.file_to_list(ip_arp_file_name, self.INPUT_DIR)
        for ip_arp_list_line in ip_arp_list:
            ip_arp_list_line = ' '.join(ip_arp_list_line.split())
            ip_arp_list_line_split = ip_arp_list_line.split()
            if len(ip_arp_list_line_split) == 6:
                if re.match(self.regex_ucast_ip, ip_arp_list_line_split[0]):
                    temp_dict[dict_key] = {'IP': ip_arp_list_line_split[0], 'MAC': ip_arp_list_line_split[2],
                                           'INTERFACE': ip_arp_list_line_split[5]}
                    dict_key += 1
        return temp_dict


class CiscoInfoCorrelater(CiscoInfoNormalizer, CiscoTelnetClass):
    """
    Class to correlate data between Cisco IOS, IOS-XR, and NX-OS
    """
    device_type_menu_dict = {
        1: {'MENU': 'IOS'},
        2: {'MENU': 'IOS-XR'},
        3: {'MENU': 'NX-OS'}}

    def __init__(self, INPUT_DIR, OUTPUT_DIR, **kwargs):
        """
        :param INPUT_DIR: The input directory
        :param OUTPUT_DIR: The output directory
        :param kwargs: keyword arguments
        :return:
        """
        LOGGER.debug('Initializing class {class_type}'.format(class_type=type(self)))
        self.INPUT_DIR = INPUT_DIR
        self.OUTPUT_DIR = OUTPUT_DIR
        CiscoInfoNormalizer.__init__(self, self.INPUT_DIR)
        self.vrf_name = kwargs.get('vrf_name')

        CiscoTelnetClass.__init__(self)

    def mroute_to_source(self, mroute_device_type_opt, mroute_file_name, cef_device_type_opt, cef_file_name):
        """
        Method that matches mroutes to source interfaces
        :param mroute_device_type_opt: Device option from device_type_menu_dict
        :param mroute_file_name: Text file of information
        :param cef_device_type_opt: Device option from device_type_menu_dict
        :param cef_file_name: Text file of information
        :return:
        """
        LOGGER.debug('Starting Method mroute_to_source in {class_type}'.format(class_type=type(self)))
        match_count = 0
        stuff_set = set()
        mcast_table_dict = dict()
        cef_table_dict = dict()
        if mroute_device_type_opt == 'IOS':
            mcast_table_dict = self.ios_mroute_to_dict(mroute_file_name)
        elif mroute_device_type_opt == 'NX-OS':
            mcast_table_dict = self.nxos_mroute_to_dict(mroute_file_name)
        elif mroute_device_type_opt == 'IOS-XR':
            mcast_table_dict = self.xr_mroute_to_dict(mroute_file_name)
        else:
            print('BAD SHIT!!')
        if cef_device_type_opt == 'IOS':
            cef_table_dict = self.ios_cef_to_dict(cef_file_name)
        elif cef_device_type_opt == 'NX-OS':
            cef_table_dict = self.nxos_cef_to_dict(cef_file_name)
        elif cef_device_type_opt == 'IOS-XR':
            cef_table_dict = self.xr_cef_to_dict(cef_file_name)
        else:
            print('BAD SHIT!!')
        mcast_table_dict_copy = dict(mcast_table_dict).copy()
        for mcast_table_dict_key in mcast_table_dict:
            ip_address, cidr_mask = ipv4.ucast_ip_mask(mcast_table_dict[mcast_table_dict_key]['SOURCE'])
            all_subnets_shorter_prefix = ipv4.all_subnets_shorter_prefix(ip_address, cidr_mask)
            for cef_table_dict_key in cef_table_dict:
                if cef_table_dict[cef_table_dict_key]['ROUTE'] in all_subnets_shorter_prefix:
                    match_count += 1
                    stuff_set.add('%s,%s,%s,%s' % (cef_table_dict[cef_table_dict_key]['ROUTE'],
                                                   mcast_table_dict[mcast_table_dict_key]['SOURCE'],
                                                   mcast_table_dict[mcast_table_dict_key]['GROUP'],
                                                   cef_table_dict[cef_table_dict_key]['INTERFACE']))
                    del mcast_table_dict_copy[mcast_table_dict_key]
                    break
        for mcast_table_dict_copy_key in mcast_table_dict_copy:
            ip_address, cidr_mask = ipv4.ucast_ip_mask(mcast_table_dict_copy[mcast_table_dict_copy_key]['SOURCE'])
            all_subnets_shorter_prefix = ipv4.all_subnets_shorter_prefix(ip_address, cidr_mask, True)
            for cef_table_dict_key in cef_table_dict:
                if cef_table_dict[cef_table_dict_key]['ROUTE'] in all_subnets_shorter_prefix:
                    match_count += 1
                    stuff_set.add('%s,%s,%s,%s' % (cef_table_dict[cef_table_dict_key]['ROUTE'],
                                                   mcast_table_dict_copy[mcast_table_dict_copy_key]['SOURCE'],
                                                   mcast_table_dict_copy[mcast_table_dict_copy_key]['GROUP'],
                                                   cef_table_dict[cef_table_dict_key]['INTERFACE']))
                    break
        pdt.list_to_file(stuff_set, 'test.txt', self. OUTPUT_DIR)
        print('MATCH TOTAL: %i' % (match_count,))
        input('PRESS <ENTER> TO CONTINUE')


if __name__ == '__main__':
    help(__name__)
