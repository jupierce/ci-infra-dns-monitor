FROM registry.ci.openshift.org/ocp/4.10:cli
RUN dnf install -y python3 python3-pip
RUN pip3 install --upgrade pip
RUN pip install openshift-client google-cloud-bigquery dnspython scapy
WORKDIR /monitor
ADD main.py .
RUN setcap cap_net_raw+eip /usr/libexec/platform-python3.6
CMD ["python3", "main.py"]
