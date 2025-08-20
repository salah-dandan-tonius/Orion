#!/bin/bash

tcpdump -i wlo1 -Z root &>/dev/null &
cap_pid=$!
sleep 2
kill "$cap_pid"
echo "killed that guy"
exit 0
