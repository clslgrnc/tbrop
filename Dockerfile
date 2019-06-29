FROM python:3.6.8-slim-stretch

WORKDIR /app/tbrop

COPY requirements.txt /app/tbrop/.
RUN pip install -r requirements.txt

COPY t-brop.py /app/tbrop/.
COPY tbrop /app/tbrop/tbrop/.

ENTRYPOINT ["python3", "t-brop.py"]
CMD ["-h"]