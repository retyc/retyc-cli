#!/bin/bash

docker run --rm --name jaeger \
	-p 16686:16686 -p 4317:4317 -p 4318:4318 \
	jaegertracing/jaeger:2.20.0
