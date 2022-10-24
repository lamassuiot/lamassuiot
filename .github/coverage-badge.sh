#!/bin/bash
float_coverage=$(</dev/stdin)
coverage=$(printf '%.0f' "$float_coverage")
R=$(((255*(100-$coverage))/100))
G=$(((255*$coverage)/100))
B=0
hex=$(printf '%02x%02x%02x\n' $R $G $B)
url=$(printf 'https://img.shields.io/badge/coverage-%s%%25-%s\n' $coverage $hex)
echo $url