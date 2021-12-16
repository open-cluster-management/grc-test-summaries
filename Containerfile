FROM quay.io/fedora/fedora:35

RUN dnf install -y python-requests python-boto3

COPY main.py /test-summaries/main.py

RUN chgrp -R 0 /test-summaries && \
    chmod -R g=u /test-summaries && \
    chmod +x /test-summaries/main.py

USER 1001
