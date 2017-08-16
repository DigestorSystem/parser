#!/usr/bin/env python
import datetime
import socket
import os

import sys
import logging

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.internet.defer import returnValue

import dpkt

import click

class DatabaseStringContainer():
    def __init__(self):
        self.compound = []

    def append_to_compound(self, string):
        self.compound.append(string)

    def get_number_strings(self):
        length = sum([1 for elem in self.compound])
        return length

    def get_elements_list(self):
        elements_list = []

        for elem in self.compound:
            elements_list.append(elem)

        return elements_list

class DatabaseIDs():
    """
    Keep track of the ids of different database tables. In particular we need

    setup_id:
        row ID of the setup that we are in right now. It is added to the
        parsed trace so that we can read which parameters were used

    node_id:
        the fixed nodes tables manages all nodes (clients and servers)
        along with their index and IP in the VM network. We use this for
        filtering traffic.
    """
    def __init__(self):
        self.setup_id = 0
        self.node_id = 0

    def set_setup_id(self, setup_id):
        self.setup_id = setup_id

class SetupParameters():
    """
    Write the setup parameters that we read from the click options into this
    parameters object. Instead of handing over all the arguments we only need
    to use this container thingy.
    """
    def __init__(self, repetitions, mix_delay, mix_rate, setup, download, num_clients, duration, window_length, tc_params, db_name):
        self.repetitions = repetitions
        self.mix_delay = mix_delay
        self.mix_rate = mix_rate
        self.setup = setup
        self.download = download
        self.num_clients = num_clients
        self.duration = duration
        self.window_length = window_length
        self.tc_params = tc_params
        self.db_name = db_name

class ConnectionMetadata():
    """
    TBD
    """

    def __init__(self, pcap, window_length, duration):
        self.cnt = []
        self.len = []
        self.iat = []
        self.ttl = []
        self.wis = []

        self.offset = 0

        stop_timestamp = 0
        first = 1
        it_cnt = 0

        for timestamp, buf in pcap:
            if first == 1:
                offset_comp = timestamp
                first = 0
            else:
                if timestamp <= duration + offset_comp:
                    stop_timestamp = timestamp
                    it_cnt += 1

        try:
            stop_timestamp = stop_timestamp - offset_comp
        except:
            logging.exception('')

        divisor, remainder = divmod(stop_timestamp, window_length)

        self.offset = offset_comp

        for i in xrange(0, int(divisor)+1):
            self.cnt.append(0)
            self.len.append(0)
            self.iat.append(0)
            self.ttl.append(0)
            self.wis.append(0)

        self.pcap_cnt = it_cnt

    def increment_metadata(self, index, length, ttl, iat, wis):
        self.cnt[index] += 1
        self.len[index] += length
        self.iat[index] += iat
        self.ttl[index] += ttl
        self.wis[index] += wis

    def get_average(self):
        for i in xrange(0, len(self.cnt)):
            if self.cnt[i] > 0:
                self.iat[i] = self.iat[i] / self.cnt[i]
                self.len[i] = self.len[i] / self.cnt[i]
                self.ttl[i] = self.ttl[i] / self.cnt[i]
                self.wis[i] = self.wis[i] / self.cnt[i]

@defer.inlineCallbacks
def write_setup_to_db(reactor, setup_parameters, dbpool, db_name, db_ids):
    columns = '(mix_delay, mix_rate, setup, download, num_clients, repetitions, duration, tc_params)'

    setup_db = '"{}"'.format(setup_parameters.setup)
    download_db = '"{}"'.format(setup_parameters.download)
    tc_db = '"{}"'.format(setup_parameters.tc_params)

    try:
        yield dbpool.runQuery('INSERT INTO {}.setups_submission {} VALUES ({},{},{},{},{},{},{},{});'.format(
            db_name,columns,
            setup_parameters.mix_delay,
            setup_parameters.mix_rate,
            setup_db,
            download_db,
            setup_parameters.num_clients,
            setup_parameters.repetitions,
            setup_parameters.duration,
            tc_db))

        id_tuple = yield dbpool.runQuery('SELECT MAX(id) FROM {}.setups_submission;'.format(db_name))
        db_ids.set_setup_id(id_tuple[0][0])
    except:
        logging.exception('')

def compose_db_string(metadata, repetition, db_ids, db_compound):
    """
    We only want to write traces to the db if the entire experiment was successful.
    That's why we first compose all the database query strings and then write them
    to the db as soon as we know the parsing was successful for the entire set of nodes.
    """
    value_string = ''

    for i in xrange(0, len(metadata.cnt)-1):
        value_string += '({},{},{},{},{},{},{},{})'.format(
            metadata.cnt[i],
            metadata.iat[i],
            metadata.len[i],
            metadata.ttl[i],
            metadata.wis[i],
            repetition,
            db_ids.setup_id,
            db_ids.node_id)

        if i < len(metadata.cnt)-2:
            value_string += ','

    db_compound.append_to_compound(value_string)

@defer.inlineCallbacks
def write_results_to_db(reactor, dbpool, db_compound_string, db_name):
    elements_list = db_compound_string.get_elements_list()

    columns = '(packet_count, inter_arrival_time, packet_length, time_to_live, window_size, repetition, setup_id, node_id)'
    for node_string in elements_list:
        if len(node_string) > 0:
            try:
                yield dbpool.runQuery('INSERT INTO {}.traces_submission {} VALUES {};'.format(
                db_name,
                    columns,
                    node_string))
            except:
                print 'Problem writing results to DB: ', err
        else:
            print 'Node string length was 0'

@defer.inlineCallbacks
def get_ip_for_node(reactor, dbpool, node_id, db_name):
    """
    We want to filter out traffic according to the IP of a node:
    When parsing a client trace we only want the incoming packets,
    when parsing a server trace we only want the outgoint packets,

    For this filtering we need the ip address of the current node, which
    can be queried from the nodes table.
    """
    query_result = yield dbpool.runQuery('SELECT node_IP FROM {}.nodes WHERE id = {};'.format(db_name,node_id))

    returnValue(query_result[0][0])

def parse_pcap(in_filename, setup_params, node_ip, node_id):
    """
    TODO
    """

    db_name = setup_params.db_name

    with open(in_filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        metadata = ConnectionMetadata(pcap, setup_params.window_length, setup_params.duration)

    with open(in_filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        iat_mem = 0.0

        cnt = 0
        limit = metadata.pcap_cnt

        for timestamp, buf in pcap:
            if cnt <= limit:
                cnt += 1

                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                    continue

                ip = eth.data
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    TCP = ip.data

                    if node_id < 31:
                        # it's a client node, we want only the incoming traffic
                        if socket.inet_ntoa(ip.dst) == node_ip:
                            temp = timestamp - metadata.offset
                            divisor = int(temp / setup_params.window_length)

                            time_diff = timestamp - iat_mem
                            iat_mem = timestamp

                            try:
                                metadata.increment_metadata(divisor, ip.len, ip.ttl, time_diff, TCP.win)
                            except Exception as err:
                                'Problem incrementing metadata thingy: ', err

                    else:
                        if socket.inet_ntoa(ip.src) == node_ip:
                            # it's a server, we want only the outgoing traffic
                            temp = timestamp - metadata.offset
                            divisor = int(temp / setup_params.window_length)

                            time_diff = timestamp - iat_mem
                            iat_mem = timestamp

                            try:
                                metadata.increment_metadata(divisor, ip.len, ip.ttl, time_diff, TCP.win)
                            except Exception as err:
                                'Problem incrementing metadata thingy: ', err
                else:
                    continue
        try:
            metadata.get_average()
        except Exception as err:
            print 'Could not get average: ', err

        return metadata

@defer.inlineCallbacks
def read_metadata(reactor, pcap_dir, setup_params, db_ids, dbpool, db_name):
    """
    Takes the setup parameters and writes them to the database.
    """

    yield write_setup_to_db(reactor, setup_params, dbpool, db_name, db_ids)

    db_compound = DatabaseStringContainer()
    for rep in xrange(1, setup_params.repetitions+1):
        db_compound = DatabaseStringContainer()

        pcap_path = '{pcap_dir}{repetition}/'.format(pcap_dir=pcap_dir, repetition=rep)

        sys.stdout.write('\r' + str(rep) + '/' + str(setup_params.repetitions))
        sys.stdout.flush()

        for item in os.listdir(pcap_path):
            if item.endswith('.pcap') and not(item.startswith('relay') or item.startswith('auth')):
                in_filename = '{path}{trace_file}'.format(path=pcap_path, trace_file=item)

                statinfo = os.stat(in_filename)
                if statinfo.st_size > 100:

                    if item.startswith('client'):
                        if item[6] == '0':
                            db_ids.node_id = int(item[7])
                        else:
                            db_ids.node_id = int(item[6:8])

                    elif item.startswith('server'):
                        if item[6] == '0':
                            db_ids.node_id = int(item[7]) + 30
                        else:
                            db_ids.node_id = int(item[6:8]) + 30

                    else:
                        break
                    node_ip = yield get_ip_for_node(reactor, dbpool, db_ids.node_id, db_name)
                    metadata = parse_pcap(in_filename, setup_params, node_ip, db_ids.node_id)

                    compose_db_string(metadata, rep, db_ids, db_compound)
                else:
                    print 'Skip {} because of size ({})'.format(item, statinfo.st_size)
                    break

        yield write_results_to_db(reactor, dbpool, db_compound, db_name)

@click.command()
@click.option('--window-length', default=0.01, type=float, help='Length of aggregation window in seconds')
@click.option('--pcap-dir', default=None, type=str, help='Directory to PCAP files')
@click.option('--repetitions', default=None, type=int, help='Number of repetitions made in a parameter setup')
@click.option('--mix-delay', default=None, type=float, help='Delay parameter used for mixing, 0 otherwise')
@click.option('--mix-rate', default=None, type=int, help='Rate parameter used for mixing, 0 otherwise')
@click.option('--setup', default=None, type=str, help='Network topology, either directed or undirected')
@click.option('--download', default=None, type=str, help='Applicatiion type, either static, random, or browsing')
@click.option('--num-clients', default=None, type=int, help='Number of Clients used in a setup')
@click.option('--duration', default=None, type=int, help='Experiment duration in seconds')
@click.option('--tc-params', default=None, type=str, help='Delay setup used for tc')
@click.option('--db-name', default=None, type=str, help='Name of benchmark database')
@click.option('--db-user', default=None, type=str, help='username for SQL db')
@click.option('--db-passwd', default=None, type=str, help='password for SQL db')
def main(window_length, pcap_dir, repetitions, mix_delay, mix_rate, setup, download, num_clients, duration, tc_params, db_name, db_user, db_passwd):
    print ''
    print 'Parse Experiment in dir {}, {} repetitions'.format(pcap_dir, repetitions)

    try:
        dbpool = adbapi.ConnectionPool('MySQLdb', host='127.0.0.1', db=db_name, user=db_user, passwd=db_passwd, port=3306)
    except:
        logging.exception('')

    db_ids = DatabaseIDs()
    setup_params = SetupParameters(repetitions, mix_delay, mix_rate, setup, download, num_clients, duration, window_length, tc_params, db_name)

    from twisted.internet import reactor
    d = read_metadata(reactor, pcap_dir, setup_params, db_ids, dbpool)
    d.addCallback(lambda ign: reactor.stop())

    reactor.run()

if __name__ == '__main__':
    main()
