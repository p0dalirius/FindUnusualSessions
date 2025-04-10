#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : FindUnusualSessions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 11 April 2025


from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smb3 import SMB3
from impacket.smbconnection import SessionError
from impacket.smb import SMB
from sectools.network.domains import is_fqdn
from sectools.network.ip import is_ipv4_cidr, is_ipv4_addr, is_ipv6_addr, expand_cidr
from sectools.windows.crypto import parse_lm_nt_hashes
from sectools.windows.ldap import get_computers_from_domain, get_subnets, raw_ldap_query, init_ldap_session
import argparse
import datetime
import dns.resolver
import os
import re
import socket
import sys
import threading
import traceback


VERSION = "1.1"


def getDomainsAndTrusts(auth_domain, auth_username, auth_password, auth_lm_hash, auth_nt_hash, auth_dc_ip, use_ldaps=False):           
    ldap_server, ldap_session = init_ldap_session(
        auth_domain=auth_domain,
        auth_dc_ip=auth_dc_ip,
        auth_username=auth_username,
        auth_password=auth_password,
        auth_lm_hash=auth_lm_hash,
        auth_nt_hash=auth_nt_hash,
        use_ldaps=use_ldaps
    )

    domainsAndtrusts = []

    ldapresults = list(ldap_session.extend.standard.paged_search(
        ldap_server.info.other["rootDomainNamingContext"][0],
        "(objectClass=domain)",
        attributes=["distinguishedName"]
    ))

    # Parse the DN to get the FQDN for all the entries
    for entry in ldapresults:
        if entry["type"] != "searchResEntry":
            continue
        dn = entry["attributes"]["distinguishedName"].upper()
        domain_parts = dn.split(',')
        domain = ""
        for part in domain_parts:
            if part.startswith("DC="):
                domain += part[3:] + "."
        domain = domain.rstrip('.')
        domainsAndtrusts.append(domain)
    
    return domainsAndtrusts


def timedeltaStr(t):
    hours, rem = divmod(t.total_seconds(), 3600)
    minutes, seconds = divmod(rem, 60)   
    if hours > 0:
        return ("%dh%dm%ds" % (hours, minutes, seconds))
    elif minutes > 0:
        return ("%dm%ds" % (minutes, seconds))
    elif seconds > 0:
        return ("%ds" % (seconds))


def export_xlsx(options, results):
    pass


def export_sqlite(options, results):
    pass


def export_json(options, results):
    pass


def is_port_open(target, port) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        # Non-existant domains cause a lot of errors, added error handling
        try:
            return s.connect_ex((target, port)) == 0
        except Exception as e:
            return False


def load_targets(options, logger):
    """
    Loads targets from various sources based on the provided options.

    This function populates the 'targets' list with domain computers, specific LDAP query results, and subnetworks of the domain.
    It checks the options provided and accordingly loads targets from different sources. If the 'no_ldap' option is set, it skips LDAP-based target loading.
    For domain computers, it uses either the default query or a specific LDAP query if provided. For subnetworks, it uses the provided subnets.
    """

    targets = []

    # Loading targets from domain computers
    if not options.no_ldap:
        if options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None) and options.target_ldap_query is None:
            logger.debug("Loading targets from computers in the domain '%s'" % options.auth_domain)
            targets += get_computers_from_domain(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=None,
                use_ldaps=options.ldaps,
                __print=False
            )

    # Loading targets from domain computers
    if not options.no_ldap:
        if options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None) and options.target_ldap_query is not None:
            logger.debug("Loading targets from specfic LDAP query '%s'" % options.target_ldap_query)
            computers = raw_ldap_query(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_username,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                query=options.target_ldap_query,
                use_ldaps=options.use_ldaps,
                attributes=["dNSHostName"]
            )
            for _, computer in computers:
                targets.append(computer["dNSHostName"])

    # Loading targets from subnetworks of the domain
    if not options.no_ldap:
        if options.subnets and options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None):
            logger.debug("Loading targets from subnetworks of the domain '%s'" % options.auth_domain)
            targets += get_subnets(
                auth_domain=options.auth_domain,
                auth_dc_ip=options.auth_dc_ip,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_hashes=options.auth_hashes,
                auth_key=None,
                use_ldaps=options.ldaps,
                __print=True
            )

    # Loading targets line by line from a targets file
    if options.targets_file is not None:
        if os.path.exists(options.targets_file):
            logger.debug("Loading targets line by line from targets file '%s'" % options.targets_file)
            f = open(options.targets_file, "r")
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            logger.error("Could not open targets file '%s'" % options.targets_file)

    # Loading targets from a single --target option
    if len(options.target) != 0:
        logger.debug("Loading targets from --target options")
        for target in options.target:
            targets.append(target)

    # Sort uniq on targets list
    targets = sorted(list(set(targets)))

    final_targets = []
    # Parsing target to filter IP/DNS/CIDR
    for target in targets:
        if is_ipv4_cidr(target):
            final_targets += [("ip", ip) for ip in expand_cidr(target)]
        elif is_ipv4_addr(target):
            final_targets.append(("ipv4", target))
        elif is_ipv6_addr(target):
            final_targets.append(("ipv6", target))
        elif is_fqdn(target):
            final_targets.append(("fqdn", target))
        else:
            logger.debug("Target '%s' was not added." % target)

    final_targets = sorted(list(set(final_targets)))
    
    return final_targets


class LogLevel(Enum):
    INFO = 0
    VERBOSE = 1
    DEBUG = 2


class Logger(object):
    """
    A Logger class that provides logging functionalities with various levels such as INFO, DEBUG, WARNING, ERROR, and CRITICAL.
    It supports color-coded output, which can be disabled, and can also log messages to a file.

    Attributes:
        __debug (bool): If True, debug level messages will be printed and logged.
        __nocolors (bool): If True, disables color-coded output.
        logfile (str|None): Path to a file where logs will be written. If None, logging to a file is disabled.

    Methods:
        __init__(debug=False, logfile=None, nocolors=False): Initializes the Logger instance.
        print(message=""): Prints a message to stdout and logs it to a file if logging is enabled.
        info(message): Logs a message at the INFO level.
        debug(message): Logs a message at the DEBUG level if debugging is enabled.
        error(message): Logs a message at the ERROR level.
    """

    def __init__(self, loglevel, logfile=None, no_colors=False):
        super(Logger, self).__init__()
        self.no_colors = no_colors
        self.loglevel = loglevel
        self.logfile = logfile
        #
        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile + (".%d"%k)):
                    k += 1
                self.logfile = self.logfile + (".%d" % k)
            open(self.logfile, "w").close()
            self.debug("Writting logs to logfile: '%s'" % self.logfile)

    def print(self, message="", end='\n'):
        """
        Prints a message to stdout and logs it to a file if logging is enabled.

        This method prints the provided message to the standard output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be printed and logged.
        """

        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print(nocolor_message, end=end)
        else:
            print(message, end=end)
        self.write_to_logfile(nocolor_message, end=end)

    def dateprint(self, message="", end='\n'):
        """
        Prints a message to stdout and logs it to a file if logging is enabled.

        This method prints the provided message to the standard output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be printed and logged.
        """

        date_str = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print("%s %s" % (date_str, nocolor_message), end=end)
        else:
            print("%s %s" % (date_str, message), end=end)
        self.write_to_logfile("%s %s" % (date_str, nocolor_message), end=end)

    def info(self, message):
        """
        Logs a message at the INFO level.

        This method logs the provided message at the INFO level. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True. The message is also logged to a file if a log file path is specified during the Logger instance initialization.

        Args:
            message (str): The message to be logged at the INFO level.
        """

        date_str = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print("%s [info] %s" % (date_str, nocolor_message))
        else:
            print("%s [\x1b[1;92minfo\x1b[0m] %s" % (date_str, message))
        self.write_to_logfile("%s [info] %s" % (date_str, nocolor_message))

    def verbose(self, message):
        """
        Logs a message at the INFO level.

        This method logs the provided message at the INFO level. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True. The message is also logged to a file if a log file path is specified during the Logger instance initialization.

        Args:
            message (str): The message to be logged at the INFO level.
        """

        if self.loglevel.value >= LogLevel.VERBOSE.value:
            date_str = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            if self.no_colors:
                print("%s [verbose] %s" % (date_str, nocolor_message))
            else:
                print("%s [\x1b[1;92mverbose\x1b[0m] %s" % (date_str, message))
            self.write_to_logfile("%s [verbose] %s" % (date_str, nocolor_message))

    def debug(self, message):
        """
        Logs a message at the DEBUG level if debugging is enabled.

        This method logs the provided message at the DEBUG level if the `debug` attribute is set to True during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be logged.
        """
        
        if self.loglevel.value >= LogLevel.DEBUG.value:
            date_str = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            if self.no_colors:
                print("%s [debug] %s" % (date_str, nocolor_message))
            else:
                print("%s [debug] %s" % (date_str, message))
            self.write_to_logfile("%s [debug] %s" % (date_str, nocolor_message))

    def warn(self, message):
        """
        Logs an error message to the console and the log file.

        This method logs the provided error message to the standard error output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The error message to be logged.
        """

        date_str = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.no_colors:
            print("%s [error] %s" % (date_str, nocolor_message))
        else:
            print("%s [\x1b[1;91merror\x1b[0m] %s" % (date_str, message))
        self.write_to_logfile("%s [error] %s" % (date_str, nocolor_message))

    def write_to_logfile(self, message, end='\n'):
        """
        Writes the provided message to the log file specified during Logger instance initialization.

        This method appends the provided message to the log file specified by the `logfile` attribute. If no log file path is specified, this method does nothing.

        Args:
            message (str): The message to be written to the log file.
        """

        if self.logfile is not None:
            f = open(self.logfile, "a")
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            f.write(nocolor_message + end)
            f.close()


class MicrosoftDNS(object):
    """
    Class to interact with Microsoft DNS servers for resolving domain names to IP addresses.
    
    Attributes:
        dnsserver (str): The IP address of the DNS server.
        verbose (bool): Flag to enable verbose mode.
        auth_domain (str): The authentication domain.
        auth_username (str): The authentication username.
        auth_password (str): The authentication password.
        auth_dc_ip (str): The IP address of the domain controller.
        auth_lm_hash (str): The LM hash for authentication.
        auth_nt_hash (str): The NT hash for authentication.
    """

    __wildcard_dns_cache = {}

    def __init__(self, dnsserver, auth_domain, auth_username, auth_password, auth_dc_ip, auth_lm_hash, auth_nt_hash, use_ldaps=False, logger=None):
        super(MicrosoftDNS, self).__init__()
        self.dnsserver = dnsserver
        
        self.auth_domain = auth_domain
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_dc_ip = auth_dc_ip
        self.auth_lm_hash = auth_lm_hash
        self.auth_nt_hash = auth_nt_hash
        self.use_ldaps = use_ldaps

        self.logger = logger

    def resolve(self, target_name):
        """
        Resolves a given target name to its corresponding IP addresses.

        This method attempts to resolve the provided target name to its IP addresses using both A and AAAA record types. It iterates through the DNS answers for each record type, appending the addresses to a list. If no records are found, it logs a debug message indicating the absence of records for the target name.

        Args:
            target_name (str): The target name to be resolved to IP addresses.

        Returns:
            list: A list of IP addresses corresponding to the target name.
        """

        target_ips = []
        for rdtype in ["A", "AAAA"]:
            dns_answer = self.getRecord(value=target_name, rdtype=rdtype)
            if dns_answer is not None:
                for record in dns_answer:
                    target_ips.append(record.address)

        if len(target_ips) == 0:
            self.logger.debug("[MicrosoftDNS] No records found for %s." % target_name)

        return target_ips

    def reverseLookup(self, target_ip, use_tcp=False):
        """
        Performs a reverse DNS lookup for a given IP address.

        This method attempts to perform a reverse DNS lookup for the provided IP address using the PTR record type. It can use either UDP or TCP protocol for the lookup, depending on the specified option. If the lookup is successful, it returns the hostname associated with the IP address. If the lookup fails or no record is found, it logs a debug message indicating the failure or absence of records.

        Args:
            target_ip (str): The IP address for which to perform the reverse DNS lookup.
            use_tcp (bool, optional): Indicates whether to use TCP protocol for the lookup. Defaults to False.

        Returns:
            str: The hostname associated with the IP address if the lookup is successful, otherwise the original IP address.
        """

        result = target_ip
        try:
            addr = dns.reversename.from_address(target_ip)
        except dns.exception.SyntaxError:
            return None
        else:
            try:
                answer = str(dns.resolver.resolve(addr, 'PTR', tcp=use_tcp)[0])
                result = answer.rstrip('.')
            except (dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
                pass
            except Exception as e:
                self.logger.debug("[MicrosoftDNS] DNS lookup failed: %s" % addr)
                pass

        return result.upper()

    def getRecord(self, rdtype, value):
        """
        Retrieves DNS records for a specified value and record type using UDP and TCP protocols.

        Parameters:
            rdtype (str): The type of DNS record to retrieve.
            value (str): The value for which the DNS record is to be retrieved.

        Returns:
            dns.resolver.Answer: The DNS answer containing the resolved records.

        Raises:
            dns.resolver.NXDOMAIN: If the domain does not exist.
            dns.resolver.NoAnswer: If the domain exists but does not have the specified record type.
            dns.resolver.NoNameservers: If no nameservers are found for the domain.
            dns.exception.DNSException: For any other DNS-related exceptions.
        """

        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = [self.dnsserver]
        dns_answer = None

        # Try UDP
        try:
            dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=False)
        except dns.resolver.NXDOMAIN:
            # the domain does not exist so dns resolutions remain empty
            pass
        except dns.resolver.NoAnswer as e:
            # domains existing but not having AAAA records is common
            pass
        except dns.resolver.NoNameservers as e:
            pass
        except dns.exception.DNSException as e:
            pass

        if dns_answer is None:
            # Try TCP
            try:
                dns_answer = dns_resolver.resolve(value, rdtype=rdtype, tcp=True)
            except dns.resolver.NXDOMAIN:
                # the domain does not exist so dns resolutions remain empty
                pass
            except dns.resolver.NoAnswer as e:
                # domains existing but not having AAAA records is common
                pass
            except dns.resolver.NoNameservers as e:
                pass
            except dns.exception.DNSException as e:
                pass

        return dns_answer

    def checkPresenceOfWildcardDns(self):
        """
        Check the presence of wildcard DNS entries in the Microsoft DNS server.

        This function queries the Microsoft DNS server to find wildcard DNS entries in the DomainDnsZones of the specified domain.
        It retrieves information about wildcard DNS entries and prints a warning message if any are found.

        Returns:
            dict: A dictionary containing information about wildcard DNS entries found in the Microsoft DNS server.
        """
        
        ldap_server, ldap_session = init_ldap_session(
            auth_domain=self.auth_domain,
            auth_dc_ip=self.auth_dc_ip,
            auth_username=self.auth_username,
            auth_password=self.auth_password,
            auth_lm_hash=self.auth_lm_hash,
            auth_nt_hash=self.auth_nt_hash,
            use_ldaps=self.use_ldaps
        )

        target_dn = "CN=MicrosoftDNS,DC=DomainDnsZones," + ldap_server.info.other["rootDomainNamingContext"][0]

        ldapresults = list(ldap_session.extend.standard.paged_search(target_dn, "(&(objectClass=dnsNode)(dc=\\2A))", attributes=["distinguishedName", "dNSTombstoned"]))

        results = {}
        for entry in ldapresults:
            if entry['type'] != 'searchResEntry':
                continue
            results[entry['dn']] = entry["attributes"]

        if len(results.keys()) != 0:
            self.logger.dateprint("[!] WARNING! Wildcard DNS entries found, dns resolution will not be consistent.")
            for dn, data in results.items():
                fqdn = re.sub(','+target_dn+'$', '', dn)
                fqdn = '.'.join([dc.split('=')[1] for dc in fqdn.split(',')])

                ips = self.resolve(fqdn)

                if data["dNSTombstoned"]:
                    self.logger.dateprint("  | %s ──> %s (set to be removed)" % (dn, ips))
                else:
                    self.logger.dateprint("  | %s ──> %s" % (dn, ips))

                # Cache found wildcard dns
                for ip in ips:
                    if fqdn not in self.__wildcard_dns_cache.keys():
                        self.__wildcard_dns_cache[fqdn] = {}
                    if ip not in self.__wildcard_dns_cache[fqdn].keys():
                        self.__wildcard_dns_cache[fqdn][ip] = []
                    self.__wildcard_dns_cache[fqdn][ip].append(data)
            print()
        return results


class RPCSessionsEnumerator(object):
    """
    RPCSessionsEnumerator is a class designed to enumerate RPC sessions on a target system. It facilitates the establishment of a DCE RPC connection to the target system, allowing for the enumeration of RPC sessions. This class is particularly useful for reconnaissance and discovery of RPC services running on a target system.

    Attributes:
        options (dict): A dictionary containing options for the enumeration process.
        address (str): The IP address of the target system.
        hostname (str): The hostname of the target system.
        username (str): The username to use for authentication.
        domain (str): The domain to use for authentication.
        password (str): The password to use for authentication.
        lmhash (str): The LM hash of the password to use for authentication.
        nthash (str): The NT hash of the password to use for authentication.
        aesKey (str): The AES key to use for authentication.
        smbconnection (object): The SMB connection object.
    """

    def __init__(self, options, midns, hostname, address, username, domain, password, lmhash='', nthash='', aesKey=None):
        self.options = options
        self.midns = midns
        # Target
        self.address = address
        self.hostname = hostname
        # Credentials
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.aesKey = aesKey

        self.smbconnection = None

    def dce_rpc_connect(self, binding, uuid):
        """
        Establishes a DCE RPC connection to the target system.

        This method sets up a DCE RPC connection to the target system using the provided binding and UUID. It configures the connection with the target's hostname and address, sets the credentials for authentication, and attempts to connect. If the connection is successful, it returns the DCE RPC object. If the connection fails due to hostname validation or other issues, it logs the error and returns None.

        Parameters:
        - binding (str): The binding string for the RPC connection.
        - uuid (str): The UUID of the RPC service to connect to.

        Returns:
        - dce (DCERPCTransportFactory): The DCE RPC object if the connection is successful, otherwise None.
        """

        try:
            self.rpc = transport.DCERPCTransportFactory(binding)
            self.rpc.set_connect_timeout(1.0)

            # Set name/host explicitly
            self.rpc.setRemoteName(self.hostname)
            self.rpc.setRemoteHost(self.address)

            # Else set the required stuff for NTLM
            if hasattr(self.rpc, "set_credentials"):
                self.rpc.set_credentials(
                    self.username, 
                    self.password,
                    domain=self.domain,
                    lmhash=self.lmhash,
                    nthash=self.nthash
                )

            dce = self.rpc.get_dce_rpc()

            # Try connecting, catch hostname validation
            try:
                dce.connect()
            except (SMB3.HostnameValidationException, SMB.HostnameValidationException) as exc:
                self.logger.info("Ignoring host %s since its hostname does not match: %s", self.hostname, str(exc))
                return None
            except SessionError as exc:
                if ("STATUS_PIPE_NOT_AVAILABLE" in str(exc) or "STATUS_OBJECT_NAME_NOT_FOUND" in str(exc)) and "winreg" in binding.lower():
                    # This can happen, silently ignore
                    return None
                if "STATUS_MORE_PROCESSING_REQUIRED" in str(exc):
                    try:
                        self.rpc.get_smb_connection().close()
                    except:
                        pass
                    # Try again!
                    return self.dce_rpc_connect(binding, uuid, False)
                # Else, just log it
                if self.options.debug:
                    traceback.print_exc()
                    self.logger.error("DCE/RPC connection failed: %s", str(exc))
                return None
            
            if self.smbconnection is None:
                self.smbconnection = self.rpc.get_smb_connection()
                # We explicity set the smbconnection back to the rpc object
                # this way it won"t be closed when we call disconnect()
                self.rpc.set_smb_connection(self.smbconnection)

            dce.bind(uuid)

        except DCERPCException as e:
            if self.options.debug:
                traceback.print_exc()
                self.logger.error("DCE/RPC connection failed: %s", str(e))
            return None
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if self.options.debug:
                traceback.print_exc()
                self.logger.error("DCE/RPC connection failed: %s", e)
            return None
        except Exception as err:
            if self.options.debug:
                self.logger.error("DCE/RPC connection failed (unknown error): %s" % err)
            return None

        return dce

    def rpc_get_sessions(self):
        """
        This function retrieves a list of active sessions on the target system.
        
        It establishes a DCE/RPC connection to the target system using the srvs.MSRPC_UUID_SRVS UUID, which is used for session enumeration.
        It then calls the hNetrSessionEnum function to enumerate the active sessions on the target system.
        The function filters out the current session of the user running the script and machine accounts.
        It computes the session time and idle time for each session and returns a list of sessions with their details.
        
        Returns:
            list: A list of active sessions on the target system, each session represented as a dictionary containing the username, session time, and idle time.
        """

        dce = self.dce_rpc_connect(r"ncacn_np:%s[\PIPE\srvsvc]" % self.address, srvs.MSRPC_UUID_SRVS)

        if dce is None:
            return []

        try:
            resp = srvs.hNetrSessionEnum(dce, "\x00", NULL, 10)
        except DCERPCException as e:
            if "rpc_s_access_denied" in str(e):
                if self.options.debug:
                    self.logger.debug("Access denied while enumerating Sessions on %s, likely a patched OS", self.hostname)
                    self.logger.error("Error: %s" % e)
                return []
            else:
                raise
        except Exception as e:
            if str(e).find("Broken pipe") >= 0:
                if self.options.debug:
                    self.logger.error("Error: %s" % e)
                return []
            else:
                raise

        sessions = []
        for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
            # Compute sessionTime 
            sessionTime = datetime.datetime.now()
            # I am removing microseconds here to avoid useless remainders
            sessionTime -= datetime.timedelta(microseconds=sessionTime.microsecond)
            sessionTime -= datetime.timedelta(seconds=session["sesi10_time"])

            # Parse sessionIdleTime (IDLE since N seconds)
            sessionIdleTime = datetime.timedelta(seconds=session["sesi10_idle_time"])

            # Parse the username of the connection
            sessionUsername = session["sesi10_username"][:-1]
            # Skip our connection
            if sessionUsername == self.username:
                continue
            # Skip empty usernames
            if len(sessionUsername) == 0:
                continue
            # Skip machine accounts
            if sessionUsername[-1] == "$":
                continue

            # Parse the source of the connection
            sessionSource = session["sesi10_cname"][:-1].upper()
            # Strip \\ from IPs
            if sessionSource[:2] == "\\\\":
                sessionSource = sessionSource[2:]
            # Skip empty IPs
            if sessionSource == "":
                continue
            # Skip local connections
            if sessionSource in ["127.0.0.1", "[::1]"]:
                continue
            # IPv6 address
            if sessionSource[0] == "[" and sessionSource[-1] == "]":
                sessionSource = sessionSource[1:-1]

            if is_ipv4_addr(sessionSource):
                machineFqdn = self.midns.reverseLookup(sessionSource)
                if machineFqdn is not None:
                    sessionSource = machineFqdn

            sessions.append({
                "username": sessionUsername, 
                "source": sessionSource, 
                "target": self.hostname.upper(),
                "sessionTime": sessionTime,
                "sessionIdleTime": sessionIdleTime
            })

        dce.disconnect()

        return sessions


def worker(options, target, domain, username, password, lmhash, nthash, registered_domains, midns, logger, results, lock):
    """
    This function is a worker that processes a target for unusual sessions. It takes in options, target information, domain, username, password, LM and NT hashes, registered domains, and a midns object. It attempts to resolve the target IP, checks if port 445 is open, and if so, enumerates RPC sessions. It then prints out information about any unusual sessions found.

    Parameters:
    - options: A dictionary of options for the script.
    - target: A tuple containing the type and data of the target.
    - domain: The domain to use for authentication.
    - username: The username to use for authentication.
    - password: The password to use for authentication.
    - lmhash: The LM hash to use for authentication.
    - nthash: The NT hash to use for authentication.
    - registered_domains: A list of registered domains.
    - midns: An object for DNS resolution.
    - results: A dictionary to store results.
    - lock: A lock object for thread-safe printing.
    """

    try:
        target_type, target_data = target
        
        target_ips = None
        target_name = ""
        if target_type.lower() in ["ip", "ipv4", "ipv6"]:
            target_name = target_data
            target_ips = [target_data]

        elif target_type.lower() in ["fqdn"]:
            target_name = target_data
            target_ips = midns.resolve(target_data)
            if target_ips is not None:
                if options.debug:
                    lock.acquire()
                    logger.debug("[+] Resolved '%s' to %s" % (target_name, target_ips))
                    lock.release()

        if target_ips is not None:
            if is_port_open(target=target_ips[0], port=445):
                rpc_sessions_enumerator = RPCSessionsEnumerator(
                    options=options,
                    midns=midns,
                    hostname=target_name,
                    address=target_ips[0],
                    username=username,
                    domain=domain,
                    password=password,
                    lmhash=lmhash,
                    nthash=nthash
                )

                sessions = rpc_sessions_enumerator.rpc_get_sessions()

                if len(sessions) != 0:
                    results["target_name"] = []
                    for session in sessions:
                        if is_ipv4_addr(session["source"]):
                            logger.dateprint(f"[\x1b[1;48;2;255;171;0;97m  Unknown  \x1b[0m] User \x1b[1;93m%s\x1b[0m is logged in on \x1b[1;93m%s\x1b[0m at \x1b[1;94m%s\x1b[0m from \x1b[1;95m%s\x1b[0m, IDLE since \x1b[1;96m%s\x1b[0m" % (
                                session["username"],
                                session["target"],
                                session["sessionTime"],
                                session["source"],
                                timedeltaStr(session["sessionIdleTime"])
                            ))

                        elif is_fqdn(session["source"]):
                            source_domain = session["source"].split('.', 1)[-1]
                            if source_domain not in registered_domains:
                                logger.dateprint(f"[\x1b[1;48;2;233;61;3;97mExt. Domain\x1b[0m] User \x1b[1;93m%s\x1b[0m is logged in on \x1b[1;93m%s\x1b[0m at \x1b[1;94m%s\x1b[0m from %s, IDLE since \x1b[1;96m%s\x1b[0m" % (
                                    session["username"],
                                    session["target"],
                                    session["sessionTime"],
                                    "\x1b[1;95m%s\x1b[0m.\x1b[1;48;2;233;61;3;97m%s\x1b[0m" % (session["source"].split('.', 1)[0], session["source"].split('.', 1)[1]),
                                    timedeltaStr(session["sessionIdleTime"])
                                ))
                            else:
                                if options.verbose or options.debug:
                                    logger.dateprint(f"[\x1b[1;48;2;83;170;51;97m   Legit   \x1b[0m] User \x1b[1;93m%s\x1b[0m is logged in on \x1b[1;93m%s\x1b[0m at \x1b[1;94m%s\x1b[0m from \x1b[1;95m%s\x1b[0m, IDLE since \x1b[1;96m%s\x1b[0m" % (
                                        session["username"],
                                        session["target"],
                                        session["sessionTime"],
                                        session["source"],
                                        timedeltaStr(session["sessionIdleTime"])
                                    ))
                        
                        else:
                            if options.verbose or options.debug:
                                logger.dateprint(f"[\x1b[1;48;2;83;170;51;97m   Legit   \x1b[0m] User \x1b[1;93m%s\x1b[0m is logged in on \x1b[1;93m%s\x1b[0m at \x1b[1;94m%s\x1b[0m from \x1b[1;95m%s\x1b[0m, IDLE since \x1b[1;96m%s\x1b[0m" % (
                                    session["username"],
                                    session["target"],
                                    session["sessionTime"],
                                    session["source"],
                                    timedeltaStr(session["sessionIdleTime"])
                                ))
                        results["target_name"].append(session)
            else:
                logger.debug("Port 445 is closed on %s (%s)" % (target_name, target_ips))

    except Exception as e:
        if options.debug:
            traceback.print_exc()


def parseArgs():
    print("FindUnusualSessions v%s - by Remi GASCOU (Podalirius)\n" % VERSION)

    parser = argparse.ArgumentParser(add_help=True, description="")

    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode. (default: False).")
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode. (default: False).")
    parser.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="Disables colored output mode.")
    parser.add_argument("-L", "--logfile", dest="logfile", metavar="LOGFILE", required=False, default=None, type=str, help="File to write logs to.")
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=64, required=False, help="Number of threads (default: 64).")
    parser.add_argument("-ns", "--nameserver", dest="nameserver", default=None, required=False, help="IP of the DNS server to use, instead of the --dc-ip.")

    group_targets_source = parser.add_argument_group("Targets")
    group_targets_source.add_argument("-tf", "--targets-file", default=None, type=str, help="Path to file containing a line by line list of targets.")
    group_targets_source.add_argument("-tt", "--target", default=[], type=str, action='append', help="Target IP, FQDN or CIDR.")
    group_targets_source.add_argument("-ad", "--auth-domain", default="", type=str, help="Windows domain to authenticate to.")
    group_targets_source.add_argument("-ai", "--auth-dc-ip", default=None, type=str, help="IP of the domain controller.")
    group_targets_source.add_argument("-au", "--auth-user", default=None, type=str, help="Username of the domain account.")
    group_targets_source.add_argument("--ldaps", default=False, action="store_true", help="Use LDAPS (default: False)")
    group_targets_source.add_argument("--no-ldap", default=False, action="store_true", help="Do not perform LDAP queries.")
    group_targets_source.add_argument("--subnets", default=False, action="store_true", help="Get all subnets from the domain and use them as targets (default: False)")
    group_targets_source.add_argument("-tl", "--target-ldap-query", dest="target_ldap_query", type=str, default=None, required=False, help="LDAP query to use to extract computers from the domain.")
    
    secret = parser.add_argument_group("Credentials")
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", default=False, action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-ap", "--auth-password", default=None, type=str, help="Password of the domain account.")
    cred.add_argument("-ah", "--auth-hashes", default=None, type=str, help="LM:NT hashes to pass the hash for this user.")
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    secret.add_argument("-k", "--kerberos", dest="auth_use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    secret.add_argument("--kdcHost", dest="auth_kdcHost", default=None, type=str, help="IP of the domain controller.")

    output = parser.add_argument_group("Output files")
    output.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    output.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    output.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.auth_password is None and options.no_pass == False and options.auth_hashes is None:
        print("[+] No password or hashes provided and --no-pass is '%s'" % options.no_pass)
        from getpass import getpass
        if options.auth_domain is not None:
            options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_user))
        else:
            options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_user)

    return options


if __name__ == '__main__':
    options = parseArgs()
    
    loglevel = LogLevel.INFO
    if options.verbose == True:
        loglevel = LogLevel.VERBOSE
    if options.debug == True:
        loglevel = LogLevel.DEBUG
    logger = Logger(loglevel=loglevel, logfile=options.logfile, no_colors=options.no_colors)

    # Parse hashes
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(options.auth_hashes)
    
    # Use AES Authentication key if available
    if options.auth_key is not None:
        options.auth_use_kerberos = True
    if options.auth_use_kerberos is True and options.auth_kdcHost is None:
        logger.warn("Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()
    
    try:
        if options.auth_dc_ip is not None and options.auth_user is not None and (options.auth_password is not None or options.auth_hashes is not None):
            midns = MicrosoftDNS(
                dnsserver=options.auth_dc_ip,
                auth_domain=options.auth_domain,
                auth_username=options.auth_user,
                auth_password=options.auth_password,
                auth_dc_ip=options.auth_dc_ip,
                auth_lm_hash=auth_lm_hash,
                auth_nt_hash=auth_nt_hash,
                use_ldaps=options.ldaps,
                logger=logger
            )
            midns.checkPresenceOfWildcardDns()

        if options.debug:
            logger.debug("[>] Parsing targets ...")
            sys.stdout.flush()

        registered_domains = getDomainsAndTrusts(
            auth_domain=options.auth_domain,
            auth_username=options.auth_user,
            auth_password=options.auth_password,
            auth_dc_ip=options.auth_dc_ip,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            use_ldaps=options.ldaps,
        )

        targets = load_targets(options, logger)

        logger.info("[+] Found %d targets." % len(targets))
        logger.info("[>] Enumerating logged in users on each computer ...")

        results = {}
        if len(targets) != 0:
            # Setup thread lock to properly write in the file
            lock = threading.Lock()
            # Waits for all the threads to be completed
            with ThreadPoolExecutor(max_workers=min(options.threads, len(targets))) as tp:
                for target in targets:
                    tp.submit(
                        worker,
                        options,
                        target,
                        options.auth_domain,
                        options.auth_user,
                        options.auth_password,
                        auth_lm_hash,
                        auth_nt_hash,
                        registered_domains,
                        midns,
                        logger,
                        results,
                        lock
                    )

            if options.export_json is not None:
                export_json(options, results)

            if options.export_xlsx is not None:
                export_xlsx(options, results)

            if options.export_sqlite is not None:
                export_sqlite(options, results)
        else:
            logger.warn("No computers parsed from the targets.")
        logger.info("[+] Bye Bye!")

    except Exception as e:
        if options.debug:
            traceback.print_exc()
        logger.warn("Error: %s" % str(e))

