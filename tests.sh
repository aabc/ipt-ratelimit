#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Simple xt_ratelimit module tester
#
# Copyright (c) 2020 <abc@openwall.com>
#

ERROR=$'\e[1;31mERROR\e[m'
SUCCESS=$'\e[1;32mSUCCESS\e[m'
trap 'set +x; echo $ERROR; exit 1' EXIT
set -efux

cd $(dirname $0)
iptables -F OUTPUT
grep -q -w ^xt_ratelimit /proc/modules && rmmod xt_ratelimit

insmod xt_ratelimit.ko
grep -w ^xt_ratelimit /proc/modules

export XTABLES_LIBDIR=$PWD:$(pkg-config --variable xtlibdir xtables)
iptables -A OUTPUT -m ratelimit --ratelimit-set test --ratelimit-mode src -j DROP

# Module use count should be 1
cat /proc/modules
! awk '$1 ~ /xt_ratelimit/ && $3 == 1 {exit 1}' /proc/modules

ls -l /proc/net/ipt_ratelimit
SET=/proc/net/ipt_ratelimit/test
cat $SET

echo +127.0.0.1 9000 > $SET
grep -qw 127.0.0.1 $SET
echo +127.0.0.2 1111 > $SET
grep -qw 127.0.0.2 $SET
echo -127.0.0.2 > $SET
! grep -qw 127.0.0.2 $SET
cat $SET

ping -f -c 100 127.0.0.1
# Will look like:
#...EEE..........................EEEE.EEEE.EEEE.EEEE.EEEEE.EEEE.EEEE.EEEE.EEEEE.EE

cat $SET

iptables -F OUTPUT

# Module use count should be 0
cat /proc/modules
! awk '$1 ~ /xt_ratelimit/ && $3 == 0 {exit 1}' /proc/modules

rmmod xt_ratelimit 2>/dev/null
set +x
trap - EXIT
echo $SUCCESS
