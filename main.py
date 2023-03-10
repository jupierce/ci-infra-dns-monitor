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
from contextlib import closing
from datetime import datetime
import json

from enum import Enum
from typing import NamedTuple, List, Optional

import dns.resolver
from scapy.all import sr1, IP, ICMP, UDP, TCP
import openshift as oc

from google.cloud import bigquery

CI_NETWORK_TABLE_ID = 'openshift-gce-devel.ci_analysis_us.infra_network_tests'
SCHEMA_LEVEL = 6

# Track in the database whether the monitor has received a SIGINT yet.
sigints_received: int = 0
process_start_time: str
cluster_id: str
node_name: str
test_variant = os.getenv('TEST_VARIANT', '')

node_info: str = None
ci_workload_active: Optional[bool] = None
ci_workload: Optional[str] = None

ci_workload_exp = re.compile(r'.*ci-workload=(\w+).*', flags=re.DOTALL)


def refresh_node_info():
    global node_info, ci_workload_active, ci_workload
    try:
        node_model = oc.selector(f'node/{node_name}').object().model
        print(f'Successfully acquired node info for {node_name}')
        if node_model.spec.unschedulable:
            ci_workload_active = False
        else:
            ci_workload_active = True

        if not ci_workload:
            if node_model.metadata.labels['ci-workload']:
                ci_workload = node_model.metadata.labels['ci-workload']
    except Exception as e:
        print(f'Error get node information for {node_name}:\n{e}')
        node_info = str(e)
        ci_workload_active = None  # Since we don't actually know whether there is a CI workload or not


def poll_node_info():
    """
    Updates oc describe of the node. The value is cached so as to not overwhelm the API server
    and will only update at most every 10 seconds.
    """
    while True:
        refresh_node_info()
        time.sleep(10)


class TestType(Enum):
    DNS_LOOKUP = 'dns_lookup'
    DNS_TCP_LOOKUP = 'dns_tcp_lookup'
    PORT_CHECK = 'port_check'
    BIGQUERY_ERROR = 'bigquery_error'
    LIVENESS_PROBE_ICMP = 'liveness_probe_icmp'
    LIVENESS_PROBE_TCP = 'liveness_probe_tcp'
    LIVENESS_PROBE_UDP = 'liveness_probe_udp'


class TargetHostTest(NamedTuple):
    hostname: str
    test_type: TestType
    port: Optional[int]


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
    node_info: Optional[str]
    ci_workload_active: Optional[bool]
    ci_workload: Optional[str]


record_q = queue.Queue()


def timestamp_str():
    return str(datetime.utcnow())


def monitor_host_port(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, node_info, ci_workload_active, process_start_time, ci_workload
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
        test_extra=f'{test_to_run.port}',
        node_info=node_info,
        ci_workload_active=ci_workload_active,
        ci_workload=ci_workload,
    )


def monitor_dns_lookup(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, node_info, ci_workload_active, process_start_time, ci_workload
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
        node_info=node_info,
        ci_workload_active=ci_workload_active,
        ci_workload=ci_workload,
    )

def _get_dns_pod_ip_addresses() -> list[str]:
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

def prob_dns_pod_liveness_icmp(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, node_info, ci_workload_active, process_start_time, ci_workload

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
        }),
        node_info=node_info,
        ci_workload_active=ci_workload_active,
        ci_workload=ci_workload,
    )

def prob_dns_pod_liveness_udp(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, node_info, ci_workload_active, process_start_time, ci_workload
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
        node_info=node_info,
        ci_workload_active=ci_workload_active,
        ci_workload=ci_workload,
    )

def prob_dns_pod_liveness_tcp(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name, node_info, ci_workload_active, process_start_time, ci_workload
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
        }),
        node_info=node_info,
        ci_workload_active=ci_workload_active,
        ci_workload=ci_workload,
    )

def bigquery_writer():
    global cluster_id, node_name, node_info, ci_workload_active, process_start_time, ci_workload

    while True:
        try:
            bq = bigquery.Client()
            while True:
                if not sigints_received:
                    time.sleep(5)  # Limit polling rate

                # Gather all records in the queue so they can be transferred with a single bigquery write.
                records = [record_q.get()]
                while not record_q.empty():
                    records.append(record_q.get())

                record_dicts = []
                for record in records:
                    record_dicts.append(record._asdict())

                errors = bq.insert_rows_json(CI_NETWORK_TABLE_ID, record_dicts)
                if len(errors) > 0:
                    print(f'ERROR: Unable to insert bigquery records: {record_dicts}\nerrors={errors}')

                    if len(record_dicts) > 10000:
                        print(f'ERROR: Discarding rows after repeated fails to insert')
                    else:
                        # Re-insert the records and try to write them again later
                        for error in errors:
                            record_q.put(records[error['index']])

                    record_q.put(ResultRecord(
                        schema_level=SCHEMA_LEVEL,
                        cluster_id=cluster_id,
                        node_name=node_name,
                        process_start_time=process_start_time,
                        test_type=TestType.BIGQUERY_ERROR.value + test_variant,
                        test_start_time=timestamp_str(),
                        test_end_time=timestamp_str(),
                        test_success=False,
                        test_msg=f'Failed to write {len(errors)} of {len(record_dicts)} records',
                        target_host='',
                        sigints_received=0,
                        test_extra='',
                        node_info=node_info,
                        ci_workload_active=ci_workload_active,
                        ci_workload=ci_workload,
                    ))

                else:
                    print(f'Wrote {len(record_dicts)} records to bigquery')
        except Exception as e:
            print(f'Error writing to bigquery: {e}')
            time.sleep(60)


def monitor_host(test_to_run: TargetHostTest, delay: int=1):
    success_count: int = 0
    while True:

        def add_result(record: ResultRecord):
            nonlocal success_count
            if record.test_success:
                success_count += 1
                if success_count % 100 == 0:
                    record_q.put(record)
            else:
                # Always record failures
                record_q.put(record)

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
        else:
            raise IOError(f'Unimplemented test type: {test_to_run.test_type}')
        time.sleep(delay)  # Limit polling rate


def sigint_handler(signum, frame):
    global sigints_received
    sigints_received += 1
    print(f'SIGINT received: {sigints_received}')


if __name__ == '__main__':
    process_start_time = timestamp_str()

    cluster_id = os.getenv('CLUSTER_ID')
    if not cluster_id:
        cluster_id = oc.selector('clusterversion').object().model.spec.clusterID

    node_name = os.getenv('NODE_NAME')
    if not node_name:
        print('NODE_NAME environment variable must be set')
        exit(1)

    delay = int(os.getenv('DELAY', '1'))

    refresh_node_info()

    tests_to_run: List[TargetHostTest] = [
        TargetHostTest('api.build01.ci.devcluster.openshift.com', TestType.PORT_CHECK, 6443),
        TargetHostTest('api.build03.ky4t.p1.openshiftapps.com', TestType.PORT_CHECK, 6443),
        TargetHostTest('api.build02.gcp.ci.openshift.org', TestType.PORT_CHECK, 6443),
        TargetHostTest('api.build04.34d2.p2.openshiftapps.com', TestType.PORT_CHECK, 6443),
        TargetHostTest('static.redhat.com', TestType.PORT_CHECK, 80),

        TargetHostTest('api.build01.ci.devcluster.openshift.com', TestType.DNS_LOOKUP, None),
        TargetHostTest('api.build03.ky4t.p1.openshiftapps.com', TestType.DNS_LOOKUP, None),
        TargetHostTest('api.build02.gcp.ci.openshift.org', TestType.DNS_LOOKUP, None),
        TargetHostTest('api.build04.34d2.p2.openshiftapps.com', TestType.DNS_LOOKUP, None),
        TargetHostTest('static.redhat.com', TestType.DNS_LOOKUP, None),

        TargetHostTest('api.build01.ci.devcluster.openshift.com', TestType.DNS_TCP_LOOKUP, None),
        TargetHostTest('api.build03.ky4t.p1.openshiftapps.com', TestType.DNS_TCP_LOOKUP, None),
        TargetHostTest('api.build02.gcp.ci.openshift.org', TestType.DNS_TCP_LOOKUP, None),
        TargetHostTest('api.build04.34d2.p2.openshiftapps.com', TestType.DNS_TCP_LOOKUP, None),
        TargetHostTest('static.redhat.com', TestType.DNS_TCP_LOOKUP, None),

        TargetHostTest('', TestType.LIVENESS_PROBE_ICMP, None),
        TargetHostTest('', TestType.LIVENESS_PROBE_UDP, None),
        # TargetHostTest('', TestType.LIVENESS_PROBE_TCP, None),
    ]
    signal.signal(signal.SIGINT, sigint_handler)

    in_q = queue.Queue()

    for test in tests_to_run:
        threading.Thread(target=monitor_host, args=(test, delay)).start()
        # monitor_host(test, delay)

    node_info_updater = threading.Thread(target=poll_node_info)
    node_info_updater.start()

    writer = threading.Thread(target=bigquery_writer)
    writer.start()
    writer.join()
