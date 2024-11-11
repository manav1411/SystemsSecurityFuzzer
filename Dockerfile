# Start from a default ubuntu image.
FROM ubuntu:22.04
FROM python:latest

# Copy/Compile my fuzzer
COPY fuzzer.py /
ADD binaries /binaries
ADD example_inputs /example_inputs
ADD src /src
RUN chmod +x /binaries/*

# Run it.
CMD ["python3", "./fuzzer.py"]
