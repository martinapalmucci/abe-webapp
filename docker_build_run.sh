#!/bin/bash

docker build -t abe-webapp:latest .
docker run -p 8000:8000 abe-webapp