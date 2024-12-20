# Start from a default ubuntu image.
FROM --platform=linux/amd64 ubuntu:latest

RUN apt-get update && apt-get install -y python3 python3-pip
RUN apt-get install -y python3-pypdf

# Copy/Compile my fuzzer
COPY . /
ADD binaries /binaries
ADD example_inputs /example_inputs
ADD wordlists /wordlists
RUN chmod +x /binaries/*

# Run it.
CMD ["python3", "fuzzer.py"]
