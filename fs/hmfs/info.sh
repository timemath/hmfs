#!/bin/sh
#you need to be root to run this shell
filename=/sys/kernel/debug/hmfs/info

echo $@ > $filename && cat $filename
