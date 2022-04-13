FROM ubuntu:latest
# FROM python:latest

WORKDIR /usr/src/app

COPY . .

RUN apt update -y
RUN apt upgrade -y
RUN apt install -y python3
RUN apt install -y python3-pip

# RUN alias python=python3

RUN python3 -m pip install python-miio
RUN python3 -m pip install flask
RUN python3 -m pip install flasgger

RUN sed -i 's/resultcallback/result_callback/g' /usr/local/lib/python3.8/dist-packages/miio/integrations/vacuum/roborock/vacuum.py; exit 0
RUN sed -i 's/resultcallback/result_callback/g' /usr/local/lib/python3.9/dist-packages/miio/integrations/vacuum/roborock/vacuum.py; exit 0
RUN sed -i 's/resultcallback/result_callback/g' /usr/local/lib/python3.10/site-packages/miio/integrations/vacuum/roborock/vacuum.py; exit 0
RUN sed -i 's/resultcallback/result_callback/g' /usr/local/lib/python3.11/site-packages/miio/integrations/vacuum/roborock/vacuum.py; exit 0
RUN sed -i 's/resultcallback/result_callback/g' /usr/local/lib/python3.12/site-packages/miio/integrations/vacuum/roborock/vacuum.py; exit 0

RUN chmod --recursive +rwx ./*

EXPOSE 5000

CMD ["python3" , "./server/server.py"]