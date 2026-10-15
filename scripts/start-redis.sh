#!/bin/bash

docker run --rm --name redis \
	-p 6379:6379 \
	redis:8.10.2
