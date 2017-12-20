#!/usr/bin/python

from copy import copy
from optparse import OptionParser, OptionValueError
import pprint
from random import seed, randint
import struct
from socket import *
from sys import exit, maxint as MAXINT
from time import time, sleep
import signal

from gz01.collections_backport import OrderedDict
from gz01.dnslib.RR import *
from gz01.dnslib.Header import Header
from gz01.dnslib.QE import QE
from gz01.inetlib.types import *
from gz01.util import *

# timeout in seconds to wait for reply
TIMEOUT = 5

# domain name and internet address of a root name server
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.240"


class ACacheEntry:
    ALPHA = 0.8

    def __init__(self, dict, srtt=None):
        self._srtt = srtt
        self._dict = dict

    def __repr__(self):
        return "<ACE %s, srtt=%s>" % \
               (self._dict, ("*" if self._srtt is None else self._srtt),)

    def update_rtt(self, rtt):
        old_srtt = self._srtt
        self._srtt = rtt if self._srtt is None else \
            (rtt * (1.0 - self.ALPHA) + self._srtt * self.ALPHA)
        logger.debug("update_rtt: rtt %f updates srtt %s --> %s" % \
                     (rtt, ("*" if old_srtt is None else old_srtt), self._srtt,))


class CacheEntry:
    def __init__(self, expiration=MAXINT, authoritative=False):
        self._expiration = expiration
        self._authoritative = authoritative

    def __repr__(self):
        now = int(time())
        return "<CE exp=%ds auth=%s>" % \
               (self._expiration - now, self._authoritative,)


class CnameCacheEntry:
    def __init__(self, cname, expiration=MAXINT, authoritative=False):
        self._cname = cname
        self._expiration = expiration
        self._authoritative = authoritative

    def __repr__(self):
        now = int(time())
        return "<CCE cname=%s exp=%ds auth=%s>" % \
               (self._cname, self._expiration - now, self._authoritative,)


# >>> entry point of ncsdns.py <<<

# Seed random number generator with current time of day:
now = int(time())
seed(now)

# Initialize the pretty printer:
pp = pprint.PrettyPrinter(indent=3)

# Initialize the name server cache data structure; 
# [domain name --> [nsdn --> CacheEntry]]:
nscache = dict([(DomainName("."),
                 OrderedDict([(DomainName(ROOTNS_DN),
                               CacheEntry(expiration=MAXINT, authoritative=True))]))])

# Initialize the address cache data structure;
# [domain name --> [in_addr --> CacheEntry]]:
# acache = dict([(DomainName(ROOTNS_DN),
#                 ACacheEntry(dict([(InetAddr(ROOTNS_IN_ADDR),
#                                    CacheEntry(expiration=MAXINT,
#                                               authoritative=True))])))])

acache = {
    DomainName(ROOTNS_DN): ACacheEntry({InetAddr(ROOTNS_IN_ADDR): CacheEntry(expiration=MAXINT, authoritative=True)}),
    DomainName('d.root-servers.net.'): ACacheEntry({InetAddr('199.7.91.13'): CacheEntry(expiration=MAXINT, authoritative=True)})
}

# Initialize the cname cache data structure;
# [domain name --> CnameCacheEntry]
cnamecache = dict([])


# Parse the command line and assign us an ephemeral port to listen on:
def check_port(option, opt_str, value, parser):
    if value < 32768 or value > 61000:
        raise OptionValueError("need 32768 <= port <= 61000")
    parser.values.port = value


class TimeoutError(Exception):
    pass


class Timeout:
    """
    Provides a context processor to handle timeouts when working with long functions.
    
    Example:
        try:
            with Timeout(seconds=2):
                time.sleep(3)
        except TimeoutError:
            logger.error("Timed out") 
    """

    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


parser = OptionParser()
parser.add_option("-p", "--port", dest="port", type="int", action="callback",
                  callback=check_port, metavar="PORTNO", default=0,
                  help="UDP port to listen on (default: use an unused ephemeral port)")
(options, args) = parser.parse_args()

# Create a server socket to accept incoming connections from DNS
# client resolvers (stub resolvers):
ss = socket(AF_INET, SOCK_DGRAM)
ss.bind(("127.0.0.1", options.port))
serveripaddr, serverport = ss.getsockname()

# NOTE: In order to pass the test suite, the following must be the
# first line that your dns server prints and flushes within one
# second, to sys.stdout:
print "%s: listening on port %d" % (sys.argv[0], serverport)
sys.stdout.flush()

# Create a client socket on which to send requests to other DNS
# servers:
setdefaulttimeout(TIMEOUT)
cs = socket(AF_INET, SOCK_DGRAM)


def resolve_iterative(question_domain, nameserver=DomainName(ROOTNS_DN)):
    logger.info("SEP:  ITERATIVE START: '{}'  =>  '{}'".format(question_domain, nameserver))

    # Nameserver itself should be resolved
    if nameserver not in acache:
        resolve_recursive(nameserver)

    # If it still isn't resolved, ignore it
    if nameserver not in acache:
        logger.info("SEP3: ITERATIVE ERROR: '{}'  =>  '{}'".format(question_domain, nameserver))
        return [], [], []

    nameserver_ip = acache[nameserver]._dict.keys()[0]

    # Check A cache
    if question_domain in acache:
        logger.info("Domain is in A-Cache")
        return [acache[question_domain]], [], []

    # Check CNAME cache
    if question_domain in cnamecache:
        logger.info("Domain is in CNAME-Cache")
        return [cnamecache[question_domain]], [], []

    # At this point the domain is definitely not in the cache, so we'll ask the nameserver

    # Build the request
    request_hdr = Header(
        id=randint(0, 65536),
        opcode=Header.OPCODE_QUERY,
        rcode=Header.RCODE_NOERR,
        qdcount=1)

    request_question = QE(
        dn=question_domain
    )

    request_data = request_hdr.pack() + request_question.pack()

    response = None
    response_hdr = None

    # ------------------------------------------------------------------------------------------
    # We'll send the UDP data to ask the nameserver about the question domain

    for _ in range(2):
        logger.info("Requesting '{}' to nameserver: '{}' ({})".format(question_domain, nameserver, nameserver_ip))

        # Send data to server
        cs.sendto(request_data, (str(nameserver_ip), 53))

        # Wait for reply
        try:
            cs.settimeout(2)
            response, _ = cs.recvfrom(512)

            # Build response header
            response_hdr = Header.fromData(response)

            # If a proper response is received, break
            if response_hdr._id == request_hdr._id:
                break

        except timeout:
            logger.info("Nameserver '{}' timed out".format(nameserver))

        if response is not None:
            break

    if response is None:
        logger.info("SEP3: ITERATIVE ERROR: '{}'  =>  '{}'".format(question_domain, nameserver))
        return [], [], []

    # ------------------------------------------------------------------------------------------
    # Process the returned resource records

    # Skip header and question entry
    resource_record_head = len(request_data)
    resource_record_quantity = response_hdr._ancount + response_hdr._nscount + response_hdr._arcount

    rr_answers = []
    rr_authoritative = []
    rr_additional = []

    # Go over each resource record
    for curr_resource_record_index in range(resource_record_quantity):

        # Fetch the current resource record
        curr_resource_record, rr_size = RR.fromData(response, resource_record_head)

        # Move the reading head
        resource_record_head += rr_size

        # Record will be authoritative if it's in the AUTHORITY SECTION (hence after the ANSWERS section)
        is_answer = curr_resource_record_index < response_hdr._ancount
        is_authoritative = not is_answer and curr_resource_record_index < response_hdr._ancount + response_hdr._nscount
        is_additional = not (is_answer or is_authoritative)

        # Store the current resource record
        if curr_resource_record._type in [RR.TYPE_A, RR.TYPE_NS, RR.TYPE_CNAME]:
            if is_answer:
                rr_answers.append(curr_resource_record)
            elif is_authoritative:
                rr_authoritative.append(curr_resource_record)
            else:
                rr_additional.append(curr_resource_record)

        # Record type A
        if curr_resource_record._type == RR.TYPE_A:
            record_address = InetAddr.fromNetwork(curr_resource_record._inaddr)
            # logger.info("Adding 'A' record for {}: {}".format(curr_resource_record._dn, record_address))
            logger.info(curr_resource_record)

            # Add to A-Cache
            if curr_resource_record._dn not in acache:
                acache[curr_resource_record._dn] = ACacheEntry({record_address: CacheEntry(expiration=curr_resource_record._ttl, authoritative=is_authoritative)})

            # Update A-Cache
            else:
                acache[curr_resource_record._dn]._dict[record_address] = CacheEntry(expiration=curr_resource_record._ttl, authoritative=is_authoritative)

        # Record type NS
        elif curr_resource_record._type == RR.TYPE_NS:
            # logger.info("Adding 'NS' record for {}: {}".format(curr_resource_record._dn, curr_resource_record._nsdn))
            logger.info(curr_resource_record)

            # Add to NS-Cache
            if curr_resource_record._dn not in nscache:
                nscache[curr_resource_record._dn] = OrderedDict({curr_resource_record._nsdn: CacheEntry(expiration=curr_resource_record._ttl, authoritative=True)})

            # Update A-Cache
            else:
                nscache[curr_resource_record._dn][curr_resource_record._nsdn] = CacheEntry(expiration=curr_resource_record._ttl, authoritative=True)

        # Record type CNAME
        elif curr_resource_record._type == RR.TYPE_CNAME:
            # logger.info("Adding 'CNAME' record for {}".format(curr_resource_record._dn))
            logger.info(curr_resource_record)

            cnamecache[curr_resource_record._dn] = CnameCacheEntry(curr_resource_record._cname, expiration=curr_resource_record._ttl)

        else:
            logger.info(curr_resource_record)

    logger.info("Received {} resource records ({} answers, {} authoritative, {} additional)".format(resource_record_quantity, len(rr_answers), len(rr_authoritative), len(rr_additional)))

    # if len(rr_answers):
    #     logger.info(rr_answers[0])
    # elif len(rr_authoritative):
    #     logger.info(rr_authoritative[0])

    logger.info("SEP3: ITERATIVE END  : '{}'  =>  '{}'".format(question_domain, nameserver))
    return rr_answers, rr_authoritative, rr_additional


def resolve_recursive(question_domain):
    """
    Performs the recursive DNS search for the given DomainName. It leverages resolve_iterative to make each query.
    :param question_domain: The DomainName to search for
    :return: True if the resolution was successful, False otherwise 
    """

    logger.info("SEP: RECURSIVE: '{}'".format(question_domain))

    nameservers = [
        [
            DomainName('d.root-servers.net.'),
            DomainName(ROOTNS_DN),
        ]
    ]

    while True:
        rr_answers, rr_authoritative, rr_additional = resolve_iterative(question_domain, nameservers[0][0])

        # If there's one A entry, return it
        if len(rr_answers):
            if question_domain in acache:
                logger.info("SEP2: RECURSIVE OK for: {}".format(question_domain))
                return True

            elif question_domain in cnamecache:
                logger.error("DUDE THIS DOMAIN ({}) IS IN CNAMECACHE BUT NOT IN ACACHE".format(question_domain))

                loc_cname, loc_a = follow_cname_chain(question_domain)
                logger.error(loc_cname)
                logger.error(loc_a)

                if not loc_a:
                    resolve_recursive(loc_cname[-1]._cname)

                logger.info("SEP2: RECURSIVE OK for: {}".format(question_domain))
                return True
            else:
                logger.info("SEP2: RECURSIVE ERROR for: {}".format(question_domain))
                return False

        # If there were no A or CNAME entries, we need to keep asking, but first let's remove the used nameserver
        nameservers[0].pop(0)

        # And cleanup the nameservers list
        if not nameservers[0]:
            nameservers.pop(0)

        # If no authoritative ns were returned but there are pending ones, ask the next one
        if not rr_authoritative and nameservers:
            continue

        # However if there no more nameservers to ask... bad stuff
        if not rr_authoritative and not nameservers:
            return False

        # If there were new authoritative nameservers, add them and iterate:
        if rr_authoritative:
            nameservers.insert(0, [x._nsdn for x in rr_authoritative])
            continue


def get_entries_in_acache(entry):
    """
    Returns a list of resource records of type A from the A cache for the given DomainName
    :param entry: Should be a DomainName to search for
    :return: list of RR_A
    """

    answers = []

    if entry in acache:
        for key in acache[entry]._dict.keys():
            answers.append(RR_A(entry, acache[entry]._dict[key]._expiration, key.toNetwork()))

    # elif entry in cnamecache:
    #     answers += get_entries_in_acache(cnamecache[entry]._cname)

    return answers

def follow_cname_chain(entry, include_a_entries=True):
    cname_entries = []
    a_entries = []

    if entry in cnamecache:
        cname_entry = cnamecache[entry]
        cname_entries.append(RR_CNAME(question._dn, cname_entry._expiration, cname_entry._cname))

        loc_cname, loc_a = follow_cname_chain(cname_entry._cname, False)

        cname_entries += loc_cname
        a_entries += loc_a

    if include_a_entries:
        for entry in cname_entries:
            a_entries += get_entries_in_acache(entry._cname)

    return cname_entries, a_entries


# This is a simple, single-threaded server that takes successive
# connections with each iteration of the following loop:
while 1:
    (data, address,) = ss.recvfrom(512)  # DNS limits UDP msgs to 512 bytes

    if not data:
        logger.error("client provided no data")
        continue

    # ------------------------------------------------------------------

    # Parse the request
    header = Header.fromData(data)

    # Ignore anything other than requests
    if header._qr != 0:
        logger.info("Ignoring non-request...")
        continue

    logger.info("Received request ({} bytes). Header:".format(len(data)))
    logger.info(header)

    # Parse current question entry
    question = QE.fromData(data, 12)

    logger.info("Received question:")
    logger.info(question)

    # Only respond to A and CNAME queries
    if question._type != QE.TYPE_A:
        logger.info("Ignoring request of type other than A...")
        continue

    answers = []
    authorities = []
    additionals = []

    # Resolve question entry, with a time limit of 60 seconds
    try:
        with Timeout(seconds=60000000):
            resolve_recursive(question._dn)

            # Get existing answers in CNAME-Cache (if any)
            if question._dn in cnamecache:

                loc_cname, loc_a = follow_cname_chain(question._dn)

                answers += loc_cname
                answers += loc_a

            # Get existing answers in A-Cache (if any)
            if question._dn in acache:
                answers += get_entries_in_acache(question._dn)

            # Fill the authority section with two nameservers of the last answer (should be a RR_A answer)
            if answers:
                last_answer = answers[-1]._dn
                parent = last_answer.parent() or '.'

                if parent in nscache:
                    # Check all entries in the NS cache for the parent of the answer
                    for key in nscache[parent].keys():

                        # Build the authority entry
                        entry = RR_NS(parent, nscache[parent][key]._expiration, key)

                        # Include authority
                        authorities.append(entry)

                        # Get glue records for the authority. Resolve it if necessary
                        # if entry._nsdn not in acache:
                        #     resolve_recursive(entry._nsdn)

                        additionals += get_entries_in_acache(entry._nsdn)

    except TimeoutError:
        logger.error("Timed out")

        # If the request timed out, don't send any RR
        answers = []
        authorities = []
        additionals = []


    # Start building the response
    response_header = Header(
        id=header._id,
        opcode=Header.OPCODE_QUERY,
        rcode=Header.RCODE_NOERR,
        qdcount=1,  # Question entries
        ancount=len(answers),
        nscount=len(authorities),
        arcount=len(additionals),
        qr=True,
        aa=False,
        tc=False,
        rd=True,
        ra=True)

    reply = response_header.pack()
    reply += question.pack()
    reply += ''.join(x.pack() for x in answers)
    reply += ''.join(x.pack() for x in authorities)
    reply += ''.join(x.pack() for x in additionals)

    # ------------------------------------------------------------------

    # logger.log(DEBUG2, "our reply in full:")
    # logger.log(DEBUG2, hexdump(reply))

    ss.sendto(reply, address)
