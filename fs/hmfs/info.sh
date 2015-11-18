#!/bin/sh
#you need to be root to run this shell
$filename=/sys/kernel/debug/hmfs/info


echo $1 > /sys/kernel/debug/hmfs/info && cat /sys/kernel/debug/hmfs/info
#if ${#1} > 50 
#then
#    echo "error: command is too long!"
#else
#    cat $filename
#fi