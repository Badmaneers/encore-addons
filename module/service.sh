# Wait until boot completed
while [ -z "$(getprop sys.boot_completed)" ]; do
	sleep 40
done

# Wait a bit more for network to come up (license check needs it)
sleep 5

MODDIR="/data/adb/modules/encore_addon_bypasschg"

# Start addon daemon
# The binary performs a license check on startup.
# If the license check fails after retries, the daemon will:
#   1. Create $MODDIR/disable (Magisk won't mount the module next boot)
#   2. Send an Android notification to the user
#   3. Exit with code 1
# If licensed, any stale "disable" flag from a previous failure is removed.
"$MODDIR/bypass_chg"
