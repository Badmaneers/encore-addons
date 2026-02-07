# shellcheck disable=SC1091,SC2181
SKIPUNZIP=1

CONFIG_PATH="/data/adb/.config/encore_addon/bypasschg"
NODE_CONFIG_PATH="$CONFIG_PATH/node_part"
ENCORE_DIR="/data/adb/modules/encore"

make_dir() {
	[ ! -d "$1" ] && mkdir -p "$1"
}

abort_unsupported_arch() {
	ui_print "*********************************************************"
	ui_print "! Unsupported Architecture: $ARCH"
	ui_print "! Your CPU architecture is not supported by this addon."
	ui_print "! If you believe this is an error, please report it to the maintainer."
	abort "*********************************************************"
}

abort_need_battdrain() {
	ui_print "*********************************************************"
	ui_print "! Battery level too high!"
	ui_print "! Please drain the battery to 95% or lower to ensure"
	ui_print "! the charging bypass test working correctly."
	abort "*********************************************************"
}

abort_need_charger() {
	ui_print "*********************************************************"
	ui_print "! Charger is not connected!"
	ui_print "! Please connect your device to a charger for testing"
	ui_print "! bypass charging functionality."
	abort "*********************************************************"
}

abort_corrupted() {
	ui_print "*********************************************************"
	ui_print "! Unable to extract verify.sh!"
	ui_print "! Installation aborted. The module may be corrupted."
	ui_print "! Please re-download and try again."
	abort "*********************************************************"
}

abort_old_encore() {
	ui_print "*********************************************************"
	ui_print "! Encore Tweaks version is too old!"
	ui_print "! Please install Encore Tweaks version 4.5 or newer."
	abort "*********************************************************"
}

alert_encore_not_installed() {
	ui_print "! Encore Tweaks is not installed!"
	ui_print "! Without it, this module will rely on its own app monitoring,"
	ui_print "! which may cause a slight performance overhead."
}

check_batt4test() {
	ui_print "- Testing bypass charging functionality..."
	ui_print ""

	# Check if this device is connected to charger
	connected=0
	for supply_path in /sys/class/power_supply/*; do
		supply=$(basename "$supply_path")
		[ "$supply" = "battery" ] && continue

		if [ -f "$supply_path/online" ]; then
			status=$(cat "$supply_path/online" 2>/dev/null)
			[ "$status" -eq 1 ] && connected=1 && break
		fi
	done

	if [ "$connected" -eq 0 ]; then
		abort_need_charger
	fi

	# Battery had to be drained at least to 95% to make sure
	# bypass charging test working correctly.
	if [ "$(dumpsys battery | awk '/level/{print $2}')" -gt 95 ]; then
		abort_need_battdrain
	fi
}

if [ -d "$ENCORE_DIR" ] && [ ! -f "$ENCORE_DIR/disable" ]; then
	encore_ver=$(grep -E '^versionCode=' "$ENCORE_DIR/module.prop" | cut -d'=' -f2)
	[ ! $encore_ver -ge 975 ] && abort_old_encore
else
	alert_encore_not_installed
fi

# Flashable integrity checkup
ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
[ ! -f "$TMPDIR/verify.sh" ] && abort_corrupted
source "$TMPDIR/verify.sh"

# Extract module files
ui_print "- Extracting module files"
extract "$ZIPFILE" 'module.prop' "$MODPATH"
extract "$ZIPFILE" 'service.sh' "$MODPATH"

# Target architecture
case $ARCH in
"arm64") ARCH_TMP="arm64-v8a" ;;
*) abort_unsupported_arch ;;
esac

# Extract executables
extract "$ZIPFILE" "libs/$ARCH_TMP/bypass_chg" "$TMPDIR"
cp "$TMPDIR"/libs/"$ARCH_TMP"/* "$MODPATH"
rm -rf "$TMPDIR/libs"

# Set configs
ui_print "- Addon configuration setup"
make_dir "$CONFIG_PATH"
[ ! -f "$CONFIG_PATH/gamelist.txt" ] && extract "$ZIPFILE" 'gamelist.txt' "$CONFIG_PATH"

# Permission settings
ui_print "- Permission setup"
chmod 0755 "$MODPATH/bypass_chg"

if [ -f "$NODE_CONFIG_PATH" ]; then
	ui_print "- Using previously tested node: $(cat "$NODE_CONFIG_PATH")"
else
	check_batt4test
fi

# Start bypass charging test
"$MODPATH/bypass_chg" --test 2>&1
[ $? -gt 0 ] && abort ""

# Easter Egg
case "$((RANDOM % 8 + 1))" in
1) ui_print "- Wooly's Fairy Tale" ;;
2) ui_print "- Sheep-counting Lullaby" ;;
3) ui_print "- Fog? The Black Shores!" ;;
4) ui_print "- Adventure? Let's go!" ;;
5) ui_print "- Hero Takes the Stage!" ;;
6) ui_print "- Woolies Save the World!" ;;
7) ui_print "- How much people will let you live for Encore?" ;;
8) ui_print "- Wen Donate?" ;;
esac
