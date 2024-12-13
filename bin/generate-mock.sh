#!/usr/bin/env bash

for file in `find . -name '*.go' | grep -v cmd`; do
    if `grep -q 'interface {' ${file}`; then
        dest=${file//internal\//}
        mockgen -source=${file} -destination=tests/mocks/${dest}
    fi
done
