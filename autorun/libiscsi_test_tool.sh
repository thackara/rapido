#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR LGPL-3.0)
# Copyright (C) SUSE S.A. 2026, all rights reserved.

_vm_ar_env_check || exit 1
_vm_ar_dyn_debug_enable

set -x
ip addr
PATH="${LIBISCSI_SRC}/test-tool:${PATH}"
set +x

chaps=""
[[ -n "${ISCSI_USER}${ISCSI_PASS}" ]] && chaps="${ISCSI_USER}%${ISCSI_PASS}@"

cat <<EOF
Ready for iSCSI testing. E.g.
iscsi-test-cu iscsi://${chaps}${INITIATOR_DISCOVERY_ADDR}:3260/${TARGET_IQN}/0

Have a lot of fun...
EOF
