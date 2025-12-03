#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR LGPL-3.0)
# Copyright (C) SUSE SA 2022-2025, all rights reserved.

target/release/rapido-cut \
	--autorun "autorun/simple_network.sh $*" \
	--install "resize ps nc hostname cat ls" \
	--net \
	--include "dracut.conf.d/.empty /rapido-rsc/cpu/1" \
	--include "dracut.conf.d/.empty /rapido-rsc/mem/512M"
