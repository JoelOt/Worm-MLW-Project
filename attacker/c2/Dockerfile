FROM python:3.9-slim
WORKDIR /c2
COPY server.py .
COPY requirements.txt .
RUN pip install -r requirements.txt
EXPOSE 8080
EXPOSE 53/udp
CMD ["python3", "server.py"]