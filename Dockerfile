FROM alpine
MAINTAINER Francesco Tornieri

RUN apk update && \
    apk add git python python-dev py-pip build-base
 
WORKDIR /wildfire

ADD wildfire /wildfire

RUN pip install -r requirements.txt

ENTRYPOINT ["python","./wildfire_send.py"]
CMD ["-h"]
