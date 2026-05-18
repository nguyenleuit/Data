FROM python:3.12-alpine

WORKDIR /app
COPY app/ /app/

ENV EVALUATOR_PORT=9091
ENV EVALUATOR_STATE_DIR=/state

EXPOSE 9091
CMD ["python", "/app/evaluator.py"]
