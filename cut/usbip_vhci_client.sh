#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR LGPL-3.0)
# Copyright (C) SUSE LLC 2024, all rights reserved.

RAPIDO_DIR="$(realpath -e ${0%/*})/.."
. "${RAPIDO_DIR}/runtime.vars"

_rt_require_dracut_args "$RAPIDO_DIR/autorun/usbip_vhci_client.sh" "$@"
_rt_require_networking
req_inst=()
_rt_require_usbip_progs req_inst

"$DRACUT" --install "tail blockdev ps rmdir stty dd grep find df sha256sum \
		   strace mkfs mkfs.xfs free lsusb ${req_inst[*]}" \
	--add-drivers "vhci-hcd usb-storage xfs" \
	--modules "base" \
	"${DRACUT_RAPIDO_ARGS[@]}" \
	"$DRACUT_OUT" || _fail "dracut failed"
