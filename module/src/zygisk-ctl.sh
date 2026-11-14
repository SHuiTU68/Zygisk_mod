MODDIR=${0%/*}/..

export TMP_PATH=/dev/.run
exec $MODDIR/bin/p64 ctl $*
