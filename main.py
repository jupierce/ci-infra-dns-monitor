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

from enum import Enum
from typing import NamedTuple, List, Optional

import dns.resolver
from scapy.all import sr, IP, ICMP, UDP
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
    icmp_liveness: Optional[bool]
    icmp_liveness_msg: Optional[str]


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
        icmp_liveness=None,
        icmp_liveness_msg=None,
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

    print(f'Checking DNS connectivity...')
    dnsservers = dns.resolver.get_default_resolver().nameservers
    print(f'DNS servers: {dnsservers}')

    # ICMP ping the DNS server
    icmp_liveness = False
    icmp_liveness_msg = ''
    print(f'Pinging DNS servers...')
    for dns_server in dnsservers:
        print(f'Pinging {dns_server}')
        try:
            ans, unans = sr(IP(dst=dns_server) / ICMP(), timeout=1.0, verbose=0)
            ans.summary()
            # retrieve the summary of the answers
            if len(ans) > 0:
                icmp_liveness = True
                print(f"DNS server {dns_server} is reachable")
            else:
                print(f'DNS server {dns_server} is not reachable')
        except Exception as e:
            icmp_liveness_msg = str(e)
            print(f'ICMP ping exception: {e}')

    # # UDP ping the DNS server port 999
    # print(f'UDP pinging DNS servers...')
    # for dns_server in dnsservers:
    #     print(f'UDP pinging {dns_server}')
    #     try:
    #         ans, unans = sr(IP(dst=dns_server) / UDP(dport=0), timeout=1.0, verbose=1)
    #         udp_liveness_msg = ans.show(dump=True)
    #         if len(ans) > 0:
    #             print(f'UDP ping {dns_server} success')
    #     except Exception as e:
    #         print(f'Exception: {e}')

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
        icmp_liveness=icmp_liveness,
        icmp_liveness_msg=icmp_liveness_msg,
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
                        icmp_liveness=None,
                        icmp_liveness_msg=None,
                    ))

                else:
                    print(f'Wrote {len(record_dicts)} records to bigquery')
        except Exception as e:
            print(f'Error writing to bigquery: {e}')
            time.sleep(60)


def monitor_host(test_to_run: TargetHostTest):
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
        else:
            raise IOError(f'Unimplemented test type: {test_to_run.test_type}')
        time.sleep(1)  # Limit polling rate


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
    ]
    signal.signal(signal.SIGINT, sigint_handler)

    in_q = queue.Queue()

    for test in tests_to_run:
        threading.Thread(target=monitor_host, args=(test,)).start()

    node_info_updater = threading.Thread(target=poll_node_info)
    node_info_updater.start()

    writer = threading.Thread(target=bigquery_writer)
    writer.start()
    writer.join()
