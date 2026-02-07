#
# verify.sh — Integrity verification for flashable module
#
# Based on the original Encore Bypass Charging Addon by Rem01Gaming
#

TMPDIR_FOR_VERIFY="$TMPDIR/.vunzip"
mkdir "$TMPDIR_FOR_VERIFY"

abort_verify() {
	ui_print "*********************************************************"
	ui_print "! $1"
	ui_print "! Installation aborted. The module may be corrupted."
	ui_print "! Please re-download and try again."
	abort "*********************************************************"
}

# Load checksums manifest from the zip
CHECKSUMS_FILE="$TMPDIR_FOR_VERIFY/checksums.sha256"
unzip -o "$ZIPFILE" "checksums.sha256" -d "$TMPDIR_FOR_VERIFY" >&2
[ -f "$CHECKSUMS_FILE" ] || abort_verify "Missing checksums.sha256 manifest"

# get_hash <file> — look up expected hash from the manifest
get_hash() {
	grep "  $1\$" "$CHECKSUMS_FILE" | awk '{print $1}'
}

# extract <zip> <file> <target dir>
extract() {
	zip=$1
	file=$2
	dir=$3

	file_path="$dir/$file"

	unzip -o "$zip" "$file" -d "$dir" >&2
	[ -f "$file_path" ] || abort_verify "$file does not exist"

	expected=$(get_hash "$file")
	if [ -n "$expected" ]; then
		actual=$(sha256sum "$file_path" | awk '{print $1}')
		[ "$actual" = "$expected" ] || abort_verify "Checksum mismatch for $file"
		ui_print "- Verified $file" >&1
	fi
}

# Verify update-binary (META-INF is already extracted by recovery)
file="META-INF/com/google/android/update-binary"
file_path="$TMPDIR_FOR_VERIFY/$file"
unzip -o "$ZIPFILE" "META-INF/com/google/android/*" -d "$TMPDIR_FOR_VERIFY" >&2
[ -f "$file_path" ] || abort_verify "$file does not exist"
expected=$(get_hash "$file")
if [ -n "$expected" ]; then
	actual=$(sha256sum "$file_path" | awk '{print $1}')
	[ "$actual" = "$expected" ] || abort_verify "Checksum mismatch for $file"
	ui_print "- Verified $file" >&1
else
	ui_print "- Download from Magisk app"
fi
