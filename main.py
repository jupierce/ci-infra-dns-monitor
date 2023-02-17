#!/usr/bin/env python3

import time
import queue
import signal
import socket
import threading
import os
from contextlib import closing
from datetime import datetime

from enum import Enum
from typing import NamedTuple, List, Optional

import dns.resolver
import openshift as oc

from google.cloud import bigquery

CI_NETWORK_TABLE_ID = 'openshift-gce-devel.ci_analysis_us.infra_network_tests'
SCHEMA_LEVEL = 1

# Track in the database whether the monitor has received a SIGINT yet.
sigints_received: int = 0
process_start_time: str
cluster_id: str
node_name: str


class TestType(Enum):
    DNS_LOOKUP = 'dns_lookup'
    PORT_CHECK = 'port_check'


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


record_q = queue.Queue()


def timestamp_str():
    return str(datetime.utcnow())


def monitor_host_port(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name
    global process_start_time
    query_start_time = timestamp_str()
    msg = None
    success = True

    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:

        try:
            sock.settimeout(10.0)
            if sock.connect_ex((test_to_run.hostname, test_to_run.port)) == 0:
                print(f"Port is open for {test_to_run.hostname}:{test_to_run.port}")
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
        test_type=TestType.PORT_CHECK.value,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=msg,
        target_host=test_to_run.hostname,
        sigints_received=sigints_received,
        test_extra=f'{test_to_run.port}'
    )


def monitor_dns_lookup(test_to_run: TargetHostTest) -> ResultRecord:
    global cluster_id, node_name
    global process_start_time
    query_start_time = timestamp_str()
    msg = None
    success = True
    answers = []

    try:
        answers = dns.resolver.resolve(test_to_run.hostname)
        print(f'Resolved {len(answers)} records for {test_to_run.hostname}')
        if len(answers) == 0:
            success = False
            msg = 'Zero records returned'
    except Exception as e:
        success = False
        msg = f'Exception: {e}'
    finally:
        query_end_time = timestamp_str()

    if not success:
        print(f'Resolution issue {test_to_run.hostname}: {msg}')

    return ResultRecord(
        schema_level=SCHEMA_LEVEL,
        cluster_id=cluster_id,
        node_name=node_name,
        process_start_time=process_start_time,
        test_type=TestType.DNS_LOOKUP.value,
        test_start_time=query_start_time,
        test_end_time=query_end_time,
        test_success=success,
        test_msg=msg,
        target_host=test_to_run.hostname,
        sigints_received=sigints_received,
        test_extra=str(len(answers)),
    )


def bigquery_writer():
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
                    print(f'Unable to insert bigquery records: {record_dicts}\nerrors={errors}')
                else:
                    print(f'Wrote {len(record_dicts)} records to bigquery')
        except Exception as e:
            print(f'Error writing to bigquery: {e}')


def monitor_host(test_to_run: TargetHostTest):
    success_count: int = 0
    while True:

        def add_result(record: ResultRecord):
            nonlocal success_count
            if record.test_success:
                success_count += 1
                if success_count % 500 == 0:
                    record_q.put(record)
            else:
                # Always record failures
                record_q.put(record)

        if test_to_run.test_type is TestType.PORT_CHECK:
            add_result(monitor_host_port(test_to_run))
        elif test_to_run.test_type is TestType.DNS_LOOKUP:
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
    ]
    signal.signal(signal.SIGINT, sigint_handler)

    in_q = queue.Queue()

    for test in tests_to_run:
        threading.Thread(target=monitor_host, args=(test,)).start()

    writer = threading.Thread(target=bigquery_writer)
    writer.start()
    writer.join()
