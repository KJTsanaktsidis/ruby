#!/usr/bin/env bash
i=0
mkdir -p $LOGDIR/{all,fail}
while true; do
    i=$((i + 1))
    LD_BIND_NOW=yes make check 2>&1 | tee -a "$LOGDIR/all/$i.log" 
    if [[ "${PIPESTATUS[0]}" != "0" ]]; then
        ln -svf "../all/$i.log" "$LOGDIR/fail/$i.log"
    fi;
done;
