# Wait until boot completed
while [ -z "$(getprop sys.boot_completed)" ]; do
	sleep 40
done

# Start addon daemon
/data/adb/modules/encore_addon_bypasschg/bypass_chg
