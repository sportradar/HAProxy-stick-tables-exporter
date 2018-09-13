#!/usr/bin/python3
import time
import socket
import sys
import re
import logging
import argparse
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY


class haproxyCollector(object):
    def __init__(self, stats_socket):
        self.stats_socket = stats_socket

    def collect(self):
        ha_stats = haproxy_Stats(self.stats_socket)
        tables = ha_stats.get_ha_sticky_tables()
        if tables is not False:
            yield self.collect_table_max_size(tables)
            yield self.collect_table_used_size(tables)

            stick_tables = ha_stats.get_ha_table_entries(tables)

            yield self.collect_table_expiry_milliseconds(stick_tables)
            yield self.collect_table_use(stick_tables)
            yield self.collect_table_conn_rate(stick_tables)
            yield self.collect_table_conn_cur(stick_tables)

    def collect_table_used_size(self, tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_used_size',
            'HAProxy stick tables entries in use',
            labels=["table"])

        for table in tables:
            metric.add_metric([table['table']], int(table['used']))

        return metric

    def collect_table_max_size(self, tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_max_size',
            'HAProxy stick table maximum entries',
            labels=["table"])

        for table in tables:
            metric.add_metric([table['table']], int(table['size']))

        return metric

    def collect_table_expiry_milliseconds(self, stick_tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_entry_expiry_milliseconds',
            'Haproxy stick table entry expires in ms',
            labels=["table", "key"])

        for table in stick_tables:
            for entry in stick_tables[table]:
                metric.add_metric([table, entry['key']], int(entry['exp']))

        return metric

    def collect_table_use(self, stick_tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_pr_entry_used_size',
            'HAProxy stick table entry used pr key ',
            labels=["table", "key"])

        for table in stick_tables:
            for entry in stick_tables[table]:
                metric.add_metric([table, entry['key']], int(entry['use']))

        return metric

    def collect_table_conn_rate(self, stick_tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_entry_conn_rate_milliseconds',
            'The lenght in milliseconds the period over which the average is measured',
            labels=["table", "key"])

        conn_rate_key = ""
        try:
            for table in stick_tables:
                for entry in stick_tables[table]:
                    for key in entry:
                        if "conn_rate" in key:
                            conn_rate_key = key
                            break
            for table in stick_tables:
                for entry in stick_tables[table]:
                    metric.add_metric([table, entry['key']], int(entry[conn_rate_key]))
        except KeyError as f:
            pass

        return metric

    def collect_table_conn_cur(self, stick_tables):
        metric = GaugeMetricFamily(
            'haproxy_stick_table_conn_cur',
            'Number of concurrent connection for a given entriy',
            labels=["table", "key"])

        try:
            for table in stick_tables:
                for entry in stick_tables[table]:
                    metric.add_metric([table, entry['key']], int(entry['conn_cur']))
        except KeyError as f:
            pass

        return metric


class haproxy_Stats(object):
    def __init__(self, stats_socket):
        self.stats_socket = stats_socket

    def connect_to_ha_socket(self, cmd):
        """ Connect to HAProxy stats socket """
        try:
            unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unix_socket.settimeout(0.1)
            unix_socket.connect(self.stats_socket)
            cmd += ' \n'
            unix_socket.send(cmd.encode())
            file_handle = unix_socket.makefile()
        except (ConnectionRefusedError, PermissionError, socket.timeout, OSError) as e:
            logging.debug(e)
            return False
        else:
            try:
                data = file_handle.read().splitlines()
            except (ConnectionResetError, ConnectionRefusedError, PermissionError, socket.timeout, OSError) as e:
                logging.debug(e)
                return False
        finally:
            unix_socket.close()

        return data

    def get_ha_sticky_tables(self):
        """
        Get a List of all HAProxy stick tables

        Returns:
            A list with Haproxy stick tables, each item
            contains a dict with key values
            [{' table': ' table_name', ' type': ' ip',
            ' size': '204800', ' used': '0'}]
        """

        try:
            raw_tables = self.connect_to_ha_socket('show table')
            if raw_tables:
                tables = []
                for line in raw_tables:
                    table_dict = {}
                    for item in line.split(','):
                        data = item.split(':')
                        if len(data) == 2:
                            key = data[0].strip('#').strip(' ')
                            value = data[1].strip(' ')
                            table_dict.update({key: value})

                    if table_dict:
                        tables.append(table_dict)
                return tables
            else:
                return False
        except IndexError:
            return False
        except TypeError:
            logging.error('Failed to connect to HAProxy Socket: {}'.format(self.stats_socket))
            return False

    def get_ha_table_entries(self, tables):
        """
        Get a list of entries in stick table for all tables

        Returns:
            A dict pr table, with a list of entries in the sticky table
        {'table1': [], 'table2': [{'key': '127.0.0.1', 'use': '0', 'exp': '1343045',
        'server_id': '1'}]}
        """
        try:
            stick_tables = {}
            for table in tables:
                table_entries = []
                raw_tables = self.connect_to_ha_socket('show table {}'.format(table['table']))
                if raw_tables:
                    for line in raw_tables:
                        item_dict = {}
                        for item in line.split(' '):
                            if '=' in item:
                                data = item.split('=')
                                if len(data) == 2:
                                    key = data[0].strip(' ')
                                    value = data[1].strip(' ')
                                    item_dict.update({key: value})
                        if item_dict:
                            table_entries.append(item_dict)
                    stick_tables.update({table['table']: table_entries})
            return stick_tables
        except IndexError:
            return False


def load_haproxy_config():
    try:
        with open('/etc/haproxy/haproxy.cfg') as f:
            config = f.read()
    except FileNotFoundError:
        logging.fatal('Haproxy config not found')
        sys.exit(1)

    stats = re.findall(r'\s+stats\s+socket\s+((\/\w+\.?\w+){0,6})', config)
    if stats:
        return stats[0][0]
    else:
        return None


if __name__ == "__main__":

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    logging.basicConfig(level=logging.DEBUG, format=log_format)
    parser = argparse.ArgumentParser(description="HAProxy stick table exporter")
    parser.add_argument('-m', '--metrics-port', type=int, default=9366)
    args = parser.parse_args()

    logging.info('Starting HAProxy sticky table exporter on port {}'.format(args.metrics_port))

    stats_socket = load_haproxy_config()
    if stats_socket is None:
        logging.fatal('Unable to find stats socket')
        sys.exit(1)

    REGISTRY.register(haproxyCollector(stats_socket))
    start_http_server(args.metrics_port)
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt as k:
            logging.info('Exiting HAProxy stick table exporter')
            print('  Exiting exporter')
            break
