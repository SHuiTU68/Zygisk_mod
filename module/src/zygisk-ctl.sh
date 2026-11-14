MODDIR=${0%/*}/..

export TMP_PATH=/dev/.zsu
exec $MODDIR/bin/zygisk-ptrace64 ctl $*
