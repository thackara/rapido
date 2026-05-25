#!/bin/bash
#
# Copyright (C) SUSE LINUX GmbH 2018, all rights reserved.
#
# This library is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation; either version 2.1 of the License, or
# (at your option) version 3.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.

_vm_ar_env_check || exit 1

set -x

modprobe iscsi_tcp

_vm_ar_dyn_debug_enable

mkdir -p /etc/iscsi /run/lock/
[ -n "$INITIATOR_IQNS" ] \
	|| _fatal "INITIATOR_IQNS config required for InitiatorName"
inames=( $INITIATOR_IQNS )
echo "InitiatorName=${inames[0]}" > /etc/iscsi/initiatorname.iscsi

echo ${OPENISCSI_SRC}/libopeniscsiusr >> /etc/ld.so.conf
export PATH="${PATH}:${OPENISCSI_SRC}/usr"

iscsid || _fatal

[ -n "$INITIATOR_DISCOVERY_ADDR" ] \
	|| _fatal "INITIATOR_DISCOVERY_ADDR config required for SendTargets"
iscsiadm -m discovery -t sendtargets -p $INITIATOR_DISCOVERY_ADDR || _fatal

# auth for normal (non-discovery) sessions
for i in /etc/iscsi/nodes/*/*/default; do
	if [[ -n "${ISCSI_USER}${ISCSI_PASS}" ]]; then
		sed -i "s#node.session.auth.authmethod = .*#node.session.auth.authmethod = CHAP#" $i
		echo "node.session.auth.username = $ISCSI_USER" >> $i
		echo "node.session.auth.password = $ISCSI_PASS" >> $i
	fi

	if [[ -n "${ISCSI_MUTUAL_USER}${ISCSI_MUTUAL_PASS}" ]]; then
		echo "node.session.auth.username_in = $ISCSI_MUTUAL_USER" >> $i
		echo "node.session.auth.password_in = $ISCSI_MUTUAL_PASS" >> $i
	fi
done

# login to all discovered targets
iscsiadm -m node -l all || _fatal
set +x
