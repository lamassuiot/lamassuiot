#!/bin/bash

for component in $(ls ci/pq_* | cut -d. -f1 | cut -d/ -f2 | cut -d_ -f2);
do
    echo "Building $component..."
    docker build -t "ghcr.io/lamassuiot/lamassu-$component:pqc" -f "ci/pq_$component.dockerfile" . >/dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        echo "Done"
        echo "Pushing $component..."
        docker push "ghcr.io/lamassuiot/lamassu-$component:pqc" >/dev/null 2>&1

        test $? -eq 0 && echo "Done" || echo "Failed"
    else
        echo "Failed"
    fi
done

