# Start from a default ubuntu image.
FROM ubuntu
FROM python:latest

RUN apt-get update && apt-get install -y python3 python3-pip

# Copy/Compile my fuzzer
COPY . /
ADD binaries /binaries
ADD example_inputs /example_inputs
RUN chmod +x /binaries/*

# Run it.
CMD ["python3", "fuzzer.py"]
