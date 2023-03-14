#!/usr/bin/env python3

import base64
import gzip
import time
import queue
import signal
import socket
import threading
import os
import re
import traceback

import urllib3
import requests
from contextlib import closing
from datetime import datetime
import json

from enum import Enum
from typing import NamedTuple, List, Optional

import dns.resolver
from scapy.all import sr1, IP, ICMP, UDP, TCP
import openshift as oc

# Records whether the monitor has received a SIGINT yet.
sigints_received: int = 0
process_start_time: str
cluster_id: str
node_name: str
test_variant = os.getenv('TEST_VARIANT', '')

SCHEMA_LEVEL = 0


class TestType(Enum):
    DNS_LOOKUP = 'dns_lookup'
    DNS_TCP_LOOKUP = 'dns_tcp_lookup'
    PORT_CHECK = 'port_check'
    BIGQUERY_ERROR = 'bigquery_error'
    LIVENESS_PROBE_ICMP = 'liveness_probe_icmp'
    LIVENESS_PROBE_TCP = 'liveness_probe_tcp'
    LIVENESS_PROBE_UDP = 'liveness_probe_udp'
    HTTP_READ = 'http_read'


class TargetHostTest(NamedTuple):
    hostname: str
    test_type: TestType
    port: Optional[int]
    bearer: Optional[str]


class ResultRecord(NamedTuple):
    schema_level: int
    cluster_id: str
    node_name: str
    process_start_time: str
    test_type: str
    test_start_time: str
    test_end_time: str
    test_success: bool
    test_msg: Optional[str]
    target_host: str
    sigints_received: int
    test_extra: Optional[str]


def timestamp_str():
    return str(datetime.utcnow())


def monitor_host_port(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, process_start_time
    query_start_time = timestamp_str()
    msg = None
    success = True

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:

        try:
            sock.settimeout(10.0)
            if sock.connect_ex((test_to_run.hostname, test_to_run.port)) == 0:
                print(f"Port is open for {test_to_run.hostname}:{test_to_run.port} {test_variant}")
            else:
                success = False
                msg = 'Port is not open'
        except Exception as e:
            success = False
            msg = f'Exception: {e}'
        finally:
            query_end_time = timestamp_str()

    if not success:
        print(f'Port check issue {test_to_run.hostname}: {msg}')

    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=TestType.PORT_CHECK.value + test_variant,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=msg,
        target_host=test_to_run.hostname,
        sigints_received=sigints_received,
        test_extra=f'{test_to_run.port}'
    )


def monitor_dns_lookup(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, process_start_time
    query_start_time = timestamp_str()
    msg = None
    success = True
    answers = []
    tcp = False

    if test_to_run.test_type is TestType.DNS_TCP_LOOKUP:
        tcp = True

    try:
        answers = dns.resolver.resolve(test_to_run.hostname, tcp=tcp)
        print(f'Resolved {len(answers)} records for {test_to_run.hostname} {test_variant} tcp={tcp}')
        if len(answers) == 0:
            success = False
            msg = 'Zero records returned'
    except Exception as e:
        success = False
        msg = f'Exception: {e}'
    finally:
        query_end_time = timestamp_str()

    if not success:
        print(f'Resolution issue {test_to_run.hostname} tcp={tcp}: {msg}')

    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=test_to_run.test_type.value + test_variant,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=msg,
        target_host=test_to_run.hostname,
        sigints_received=sigints_received,
        test_extra=str(len(answers)),
    )


def _get_dns_pod_ip_addresses() -> List[str]:
    with oc.project('openshift-dns'):
        get_conditions = lambda x: x.get('status', {}).get('conditions', [])
        get_condition = lambda x: [i.get('status') for i in x if i.get('type') == 'Ready']
        is_ready = lambda x: get_condition(get_conditions(x)) == ['True']

        pods = oc.selector('pod').objects()
        pods = [pod for pod in pods if pod.name().startswith('dns-default')]
        pods = [pod for pod in pods if is_ready(pod.as_dict())]

        ip_addresses = [pod.as_dict().get('status', {}).get('podIP') for pod in pods]
        print(f'Found {len(ip_addresses)} DNS pods')
        ip_addresses = [ip for ip in ip_addresses if ip is not None]
        print(f'Found {len(ip_addresses)} DNS pods IP addresses')
        return ip_addresses


def http_read(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, process_start_time
    headers = dict()
    if test_to_run.bearer:
        headers['Authorization'] = f'Bearer {test_to_run.bearer}'
    start_time = timestamp_str()
    success = False
    status_code = -1
    msg = ''
    try:
        response = requests.get(test_to_run.hostname, headers=headers, verify=False, timeout=5)
        status_code = response.status_code
        success = status_code == 200
    except Exception as e:
        traceback.print_exc()
        msg = str(e)

    end_time = timestamp_str()
    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=test_to_run.test_type,
        test_start_time=start_time,
        test_end_time=end_time,
        test_success=success,
        test_msg=msg,
        target_host=test_to_run.hostname,
        sigints_received=sigints_received,
        test_extra=str(status_code)
    )


def prob_dns_pod_liveness_icmp(_: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, process_start_time

    print(f'Checking DNS pod connectivity by ICMP...')
    query_start_time = timestamp_str()
    # Retrieve the DNS pods
    ip_addresses = _get_dns_pod_ip_addresses()

    # ICMP ping the DNS server
    reachable = []
    print(f'Pinging DNS pods...')
    success = True
    for dns_server in ip_addresses:
        print(f'Pinging {dns_server}')
        ans = sr1(IP(dst=dns_server) / ICMP(), timeout=1.0, verbose=1)
        if not ans:
            print(f'Response: no answer')
        else:
            print(f'Response: {ans.summary()}')
        # retrieve the summary of the answers
        if ans and ans.haslayer(ICMP) and ans[ICMP].type == 0:
            print(f"DNS server {dns_server} is reachable")
            reachable.append(dns_server)
        else:
            print(f'DNS server {dns_server} is not reachable')
        success = False
    query_end_time = timestamp_str()
    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=TestType.LIVENESS_PROBE_ICMP,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=f'ICMP pinged {len(ip_addresses)} DNS pods, {len(reachable)} reachable, {len(ip_addresses)-len(reachable)} unreachable',
        target_host='',
        sigints_received=sigints_received,
        test_extra=json.dumps({
            'reachable': reachable,
            'unreachable': [ip for ip in ip_addresses if ip not in reachable],
        })
    )


def prob_dns_pod_liveness_udp(_: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, process_start_time
    print(f'Checking DNS pod connectivity by UDP...')
    query_start_time = timestamp_str()
    # Retrieve the DNS pods
    ip_addresses = _get_dns_pod_ip_addresses()

    # UDP ping the DNS server
    print(f'UDP pinging DNS servers...')
    reachable = []
    success = True
    for dns_server in ip_addresses:
        print(f'UDP pinging {dns_server}')
        ans = sr1(IP(dst=dns_server) / UDP(dport=0), timeout=1.0, verbose=1)
        if not ans:
            print(f'Response: no answer')
        else:
            print(f'Response: {ans.summary()}')
        if ans and ans[ICMP].type == 3 and ans[ICMP].code == 3:
            print(f'DNS server {dns_server} is reachable')
            reachable.append(dns_server)
        else:
            print(f'DNS server {dns_server} is not reachable')
            success = False
    query_end_time = timestamp_str()
    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=TestType.LIVENESS_PROBE_UDP,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=f'UDP pinged {len(ip_addresses)} DNS pods, {len(reachable)} reachable, {len(ip_addresses)-len(reachable)} unreachable',
        target_host='',
        sigints_received=sigints_received,
        test_extra=json.dumps({
            'reachable': reachable,
            'unreachable': [ip for ip in ip_addresses if ip not in reachable],
        }),
    )


def prob_dns_pod_liveness_tcp(_: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, process_start_time
    print(f'Checking DNS pod connectivity by TCP...')
    query_start_time = timestamp_str()
    # Retrieve the DNS pods
    ip_addresses = _get_dns_pod_ip_addresses()

    # TCP ping the DNS server
    print(f'TCP pinging DNS servers...')
    reachable = []
    success = True
    for dns_server in ip_addresses:
        print(f'TCP pinging {dns_server}')
        ans = sr1(IP(dst=dns_server) / TCP(dport=53, flags='S'), timeout=1.0, verbose=1)
        if not ans:
            print(f'Response: no answer')
        else:
            print(f'Response: {ans.summary()}')
        if ans and ans.haslayer(TCP) and ans[TCP].flags == 'SA':
            print(f'DNS server {dns_server} is reachable')
        else:
            print(f'DNS server {dns_server} is not reachable')

    query_end_time = timestamp_str()
    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=TestType.LIVENESS_PROBE_TCP,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=f'TCP pinged {len(ip_addresses)} DNS pods, {len(reachable)} reachable, {len(ip_addresses)-len(reachable)} unreachable',
        target_host='',
        sigints_received=sigints_received,
        test_extra=json.dumps({
            'reachable': reachable,
            'unreachable': [ip for ip in ip_addresses if ip not in reachable],
        })
    )


def monitor_host(test_to_run: TargetHostTest, delay: int = 1):
    success_count: int = 0
    while True:

        def add_result(record: ResultRecord):
            nonlocal success_count
            if record.test_success:
                if success_count % 60 == 0:
                    print(f'Success: {record}')
                success_count += 1
            else:
                # Always record failures
                print(f'ERROR: {record}')
                success_count = 0

        try:
            if test_to_run.test_type is TestType.PORT_CHECK:
                add_result(monitor_host_port(test_to_run))
            elif test_to_run.test_type is TestType.DNS_LOOKUP or test_to_run.test_type is TestType.DNS_TCP_LOOKUP:
                add_result(monitor_dns_lookup(test_to_run))
            elif test_to_run.test_type is TestType.LIVENESS_PROBE_ICMP:
                add_result(prob_dns_pod_liveness_icmp(test_to_run))
            elif test_to_run.test_type is TestType.LIVENESS_PROBE_TCP:
                add_result(prob_dns_pod_liveness_tcp(test_to_run))
            elif test_to_run.test_type is TestType.LIVENESS_PROBE_UDP:
                add_result(prob_dns_pod_liveness_udp(test_to_run))
            elif test_to_run.test_type is TestType.HTTP_READ:
                add_result(http_read(test_to_run))
            else:
                raise IOError(f'Unimplemented test type: {test_to_run.test_type}')
        except Exception:
            traceback.print_exc()
        time.sleep(delay)  # Limit polling rate


def sigint_handler(_, __):
    global sigints_received
    sigints_received += 1
    print(f'SIGINT received: {sigints_received}')


if __name__ == '__main__':
    urllib3.disable_warnings()
    process_start_time = timestamp_str()

    cluster_id = os.getenv('CLUSTER_ID')
    if not cluster_id:
        cluster_id = oc.selector('clusterversion').object().model.spec.clusterID

    node_name = os.getenv('NODE_NAME')
    if not node_name:
        print('NODE_NAME environment variable must be set')
        exit(1)

    token = oc.get_auth_token()

    delay = int(os.getenv('DELAY', '1'))

    tests_to_run: List[TargetHostTest] = [
        TargetHostTest('172.30.0.1', test_type=TestType.PORT_CHECK, port=443, bearer=None),
        TargetHostTest('https://172.30.0.1/healthz',
                       test_type=TestType.HTTP_READ, port=443, bearer=None),
        # TargetHostTest('https://prometheus-k8s.openshift-monitoring.svc.cluster.local:9091/api/v1/query?query=test', test_type=TestType.HTTP_READ, port=443, bearer=token),
    ]
    signal.signal(signal.SIGINT, sigint_handler)

    in_q = queue.Queue()

    for test in tests_to_run:
        threading.Thread(target=monitor_host, args=(test, delay)).start()

    while True:
        sleep(60)
