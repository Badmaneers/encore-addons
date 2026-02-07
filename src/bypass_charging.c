/**
 * bypass_charging.c — Bypass charging hardware detection and control
 *
 * Reconstructed from Ghidra pseudocode:
 *   FUN_0060d2e0 (test mode section)  → run_bypass_test()
 *   Data tables at 00673b60..00674890 → bypass method table
 *   FUN_0060e94c                      → sysfs node writing
 *
 * The binary has a compiled-in table of 49 (0x31) bypass charging methods,
 * each with a name (e.g. "OPLUS_MMI", "TRANSISSION_BYPASSCHG") and a list
 * of sysfs node paths + enable/disable values.
 *
 * The table at 00674890 (PTR_PTR_s_OPLUS_MMI) is an array of structs:
 *   struct bypass_method {
 *       char *name;          // offset +0x00
 *       uint32_t id;         // offset +0x08
 *       void *nodes;         // offset +0x10  → array of sysfs_node_op
 *       long node_count;     // offset +0x18
 *   }
 *
 * Each sysfs_node_op (24 bytes / 3 pointers):
 *   struct sysfs_node_op {
 *       char *enable_path;   // offset +0x00
 *       char *disable_path;  // offset +0x08  (usually same path)
 *       char *value;         // offset +0x10  (enable value at [+0x10], disable at [+0x08])
 *   }
 *
 * The enable sequence iterates: (nodes[i] + 0x10) path, write (nodes[i]) value
 * The disable sequence iterates: (nodes[i] + 0x08) path, write (nodes[i]) value
 *
 * IMPORTANT: The exact sysfs paths and values are vendor-specific. This
 * reconstruction includes the most common known methods. The original binary
 * has 49 methods — the full table would require the binary's rodata section.
 */

#include "bypass_charging.h"
#include "logging.h"
#include <stdarg.h>
#include <sys/file.h>

/* Forward declaration from file_io.c */
extern int write_file_formatted(const char *path, int append, int use_flock,
                                const char *fmt, ...);

/* ─── Known bypass charging methods ──────────────────────────────────
 *
 * Reconstructed from string references in the binary:
 *   00673b60: "OPLUS_MMI"
 *   00673b80: "TRANSISSION_BYPASSCHG"
 *   ...and many more
 *
 * The config name → method index lookup at 00673b60 iterates
 * with stride 0x20, and the test loop at 00674890 iterates with
 * stride sizeof(void*) up to 0x31 entries.
 *
 * NOTE: Sysfs paths are inferred from common Android kernel interfaces.
 *       The original binary hardcodes vendor-specific paths that may vary.
 * ─────────────────────────────────────────────────────────────────── */

/* ── OPLUS/Realme: mmi_charging_enable ─────────────────────────────── */
static sysfs_node_op_t oplus_mmi_nodes[] = {
    {
        .path          = "/sys/class/oplus_chg/battery/mmi_charging_enable",
        .disable_value = "1",
        .enable_value  = "0",
    },
};

/* ── Transsion/Infinix/Tecno ───────────────────────────────────────── */
static sysfs_node_op_t transsion_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/input_suspend",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── Xiaomi: battery_charging_enabled ──────────────────────────────── */
static sysfs_node_op_t xiaomi_batt_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/battery_charging_enabled",
        .disable_value = "1",
        .enable_value  = "0",
    },
};

/* ── Samsung: store_mode ───────────────────────────────────────────── */
static sysfs_node_op_t samsung_store_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/store_mode",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── Generic: input_suspend ────────────────────────────────────────── */
static sysfs_node_op_t generic_input_suspend_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/input_suspend",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── Qualcomm: charge_disable ──────────────────────────────────────── */
static sysfs_node_op_t qcom_charge_disable_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/charge_disable",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── MTK: stop_charging ────────────────────────────────────────────── */
static sysfs_node_op_t mtk_stop_charging_nodes[] = {
    {
        .path          = "/proc/mtk_battery_cmd/current_cmd",
        .disable_value = "0 1",
        .enable_value  = "0 0",
    },
};

/* ── OnePlus: op_disable_charge ────────────────────────────────────── */
static sysfs_node_op_t oneplus_disable_charge_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/op_disable_charge",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── Huawei: charge_enable ─────────────────────────────────────────── */
static sysfs_node_op_t huawei_charge_enable_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/charge_enable",
        .disable_value = "1",
        .enable_value  = "0",
    },
};

/* ── Google Pixel: charge_disable ──────────────────────────────────── */
static sysfs_node_op_t pixel_charge_disable_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/charge_disable",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── ASUS: charging_suspend ────────────────────────────────────────── */
static sysfs_node_op_t asus_charging_suspend_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/charging_suspend",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/* ── Sony: charging_enabled ────────────────────────────────────────── */
static sysfs_node_op_t sony_charging_enabled_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/charging_enabled",
        .disable_value = "1",
        .enable_value  = "0",
    },
};

/* ── Vivo: vivo_batt_stop_chg ──────────────────────────────────────── */
static sysfs_node_op_t vivo_stop_chg_nodes[] = {
    {
        .path          = "/sys/class/power_supply/battery/batt_stop_chg",
        .disable_value = "0",
        .enable_value  = "1",
    },
};

/**
 * Master table of bypass charging methods.
 *
 * The original binary has 49 entries at PTR_PTR_s_OPLUS_MMI_00674890.
 * The config file lookup at 00673b60 iterates with stride 0x20 (32 bytes)
 * through the name→index map (0x620/0x20 = 49 entries).
 *
 * We reconstruct the most important ones here. Unknown methods use
 * placeholder entries with the generic input_suspend mechanism.
 *
 * CONFIDENCE:
 *   - OPLUS_MMI: HIGH (directly observed string)
 *   - TRANSISSION_BYPASSCHG: HIGH (directly observed string)
 *   - Others: MEDIUM (inferred from common Android kernel interfaces)
 */
static bypass_method_t bypass_methods[] = {
    /* Index  0 */ { "OPLUS_MMI",              1, oplus_mmi_nodes },
    /* Index  1 */ { "TRANSISSION_BYPASSCHG",  1, transsion_nodes },
    /* Index  2 */ { "XIAOMI_BATT",            1, xiaomi_batt_nodes },
    /* Index  3 */ { "SAMSUNG_STORE",          1, samsung_store_nodes },
    /* Index  4 */ { "GENERIC_INPUT_SUSPEND",  1, generic_input_suspend_nodes },
    /* Index  5 */ { "QCOM_CHARGE_DISABLE",    1, qcom_charge_disable_nodes },
    /* Index  6 */ { "MTK_STOP_CHARGING",      1, mtk_stop_charging_nodes },
    /* Index  7 */ { "ONEPLUS_DISABLE_CHARGE", 1, oneplus_disable_charge_nodes },
    /* Index  8 */ { "HUAWEI_CHARGE_ENABLE",   1, huawei_charge_enable_nodes },
    /* Index  9 */ { "PIXEL_CHARGE_DISABLE",   1, pixel_charge_disable_nodes },
    /* Index 10 */ { "ASUS_CHARGING_SUSPEND",  1, asus_charging_suspend_nodes },
    /* Index 11 */ { "SONY_CHARGING_ENABLED",  1, sony_charging_enabled_nodes },
    /* Index 12 */ { "VIVO_BATT_STOP_CHG",     1, vivo_stop_chg_nodes },
    /* Remaining indices 13..48: generic fallbacks — original binary
     * has vendor-specific variants with different sysfs paths.
     * Placeholder until full rodata is extracted. */
};

#define NUM_KNOWN_METHODS  (sizeof(bypass_methods) / sizeof(bypass_methods[0]))

const bypass_method_t *get_bypass_methods(void)
{
    return bypass_methods;
}

/**
 * read_node_config — Read the bypass charging method from the config file
 *
 * Reconstructed from FUN_0060d2e0 (main function, daemon path):
 *   1. fopen("/data/adb/.config/encore_addon/bypasschg/node_part", "r")
 *   2. fgets(buf, 0x40)
 *   3. strcspn(buf, "\n") to strip newline
 *   4. Loop through name→index table at 00673b60 (stride 0x20) up to 0x620
 *   5. strcmp each name → return index on match
 *   6. Exit on failure: "failed to parse NodePart config for bypass charging!"
 *
 * @return Method index (0..MAX_BYPASS_METHODS-1) or -1 on error
 */
int read_node_config(void)
{
    FILE *f = fopen(PATH_NODE_CONFIG, "r");
    if (!f) {
        char *err = strerror(errno);
        log_message(LOG_FATAL, "read_node_config: Unable to open NodePart config: %s", err);
        return -1;
    }

    char buf[64];
    char *ret = fgets(buf, sizeof(buf), f);
    fclose(f);

    if (!ret) {
        char *err = strerror(errno);
        log_message(LOG_ERROR, "read_node_config: Unable to read NodePart config: %s", err);
        return -1;
    }

    /* Strip trailing newline */
    buf[strcspn(buf, "\n")] = '\0';

    /* Search for matching method name */
    for (size_t i = 0; i < NUM_KNOWN_METHODS; i++) {
        if (strcmp(buf, bypass_methods[i].name) == 0) {
            return (int)i;
        }
    }

    log_message(LOG_ERROR, "failed to parse NodePart config for bypass charging!");
    return -1;
}

/**
 * bypass_enable — Enable bypass charging for the given method
 *
 * Reconstructed from main function's enable path:
 *   Iterates nodes[i], writes enable_value to enable_path:
 *     puVar8 = (lVar6 + 0x10);  // start at nodes + 0x10
 *     FUN_0060e94c(puVar8[-2], 0, 0, *puVar8);  // write(path[-2], value[0])
 *     puVar8 += 3;  // stride of 3 pointers = 24 bytes
 */
void bypass_enable(int method_index)
{
    if (method_index < 0 || (size_t)method_index >= NUM_KNOWN_METHODS)
        return;

    const bypass_method_t *m = &bypass_methods[method_index];
    for (int i = 0; i < m->node_count; i++) {
        write_file_formatted(m->nodes[i].path, 0, 0,
                             "%s", m->nodes[i].enable_value);
    }
}

/**
 * bypass_disable — Disable bypass charging for the given method
 *
 * Reconstructed from main function's disable path:
 *   Iterates nodes[i], writes disable_value to disable_path:
 *     puVar8 = (lVar6 + 0x08);  // start at nodes + 0x08
 *     FUN_0060e94c(puVar8[-1], 0, 0, *puVar8);  // write(path[-1], value[0])
 *     puVar8 += 3;
 */
void bypass_disable(int method_index)
{
    if (method_index < 0 || (size_t)method_index >= NUM_KNOWN_METHODS)
        return;

    const bypass_method_t *m = &bypass_methods[method_index];
    for (int i = 0; i < m->node_count; i++) {
        write_file_formatted(m->nodes[i].path, 0, 0,
                             "%s", m->nodes[i].disable_value);
    }
}

/**
 * read_battery_current_ma — Read battery current in milliamps
 *
 * Reconstructed from multiple locations in FUN_0060d2e0:
 *   1. fopen("/sys/class/power_supply/battery/current_now", "r")
 *   2. fgets(buf, 0x20)
 *   3. atoi(buf) → make absolute value → divide by 1000 if g_current_ma_scale==1
 *
 * The scaling logic:
 *   - Some kernels report µA (microamps), divide by 1000 → mA
 *   - Some kernels report mA directly
 *   - g_current_ma_scale is set to 1 if initial readings > 12000 (meaning µA)
 */
int read_battery_current_ma(void)
{
    FILE *f = fopen(PATH_BATTERY_CURRENT, "r");
    if (!f) {
        char *err = strerror(errno);
        printf("Failed to read current: %s", err);
        return -1;
    }

    char buf[32];
    char *ret = fgets(buf, sizeof(buf), f);
    fclose(f);

    if (!ret) return -1;

    int raw = atoi(buf);
    int abs_val = (raw < 0) ? -raw : raw;

    /* Scale if kernel reports in µA */
    if (g_current_ma_scale) {
        return abs_val / 1000;
    }
    return abs_val;
}

/**
 * run_bypass_test — Interactive bypass charging hardware detection
 *
 * Reconstructed from FUN_0060d2e0 --test path (when config doesn't exist):
 *
 * Phase 1: Detect µA vs mA scaling
 *   - Read current_now 6 times over 6 seconds
 *   - If any reading > 12000, set g_current_ma_scale = 1
 *
 * Phase 2: Iterate all bypass methods
 *   - For each method with valid sysfs nodes:
 *     a. Try writing enable values to all nodes
 *     b. If all writes succeed (return 0), skip this method
 *     c. Wait 10 seconds for charging to settle
 *     d. Take 15 current readings over 15 seconds
 *     e. Compute average current in mA
 *     f. If avg < 80.0 mA → method works!
 *        Save method name to config and exit
 *     g. Else → restore disable values and try next
 *
 * Phase 3: If no method works, print failure and exit
 */
void run_bypass_test(void)
{
    puts("Testing all bypass charging methods...");

    /* Phase 1: Detect µA vs mA scaling.
     *
     * Original binary (line ~107): reads current 6 times (uVar9 < 5, post-increment).
     * Logic: take abs(atoi(current_now)), tentatively divide by 1000.
     * If DAT_00681cd8 (g_current_ma_scale) is still 0, use the RAW value instead.
     * If the chosen value > 12000, set g_current_ma_scale = 1.
     *
     * This means: first time through, it checks raw µA against 12000.
     * Once flagged as µA mode, subsequent readings use divided (mA) value.
     */
    for (int i = 0; i < 6; i++) {
        sleep(1);

        FILE *f = fopen(PATH_BATTERY_CURRENT, "r");
        if (!f) {
            printf("Failed to read current: %s", strerror(errno));
            continue;
        }

        char buf[32];
        char *ret = fgets(buf, 0x20, f);
        fclose(f);
        if (!ret) continue;

        int raw = atoi(buf);
        uint32_t abs_val = (raw < 0) ? (uint32_t)(-raw) : (uint32_t)raw;
        uint32_t check_val = abs_val / 1000;

        /* If µA mode NOT yet detected, use raw value for threshold check */
        if (g_current_ma_scale == 0) {
            check_val = abs_val;
        }

        if (check_val > 12000) {
            g_current_ma_scale = 1;
        }
    }

    if (g_current_ma_scale & 1) {
        puts("Detected microamp reporting, scaling to milliamps.");
    }

    /* Phase 2: Test each method.
     *
     * Original binary (line ~130): iterates PTR_PTR_s_OPLUS_MMI_00674890[0..0x30]
     * For each method:
     *   - Skip if nodes ptr == NULL or node_count == 0
     *   - Try writing enable_value to path for all nodes
     *   - Sentinel check: iVar5 starts 0xff, if ALL writes return 0 → iVar10=0
     *   - If any write fails, skip this method silently
     *   - If all succeed: wait 10s, take 15 current samples, compute avg
     *   - If avg < 80.0 mA → save config and break
     *   - Else → restore disable values and continue
     */
    for (size_t idx = 0; idx < NUM_KNOWN_METHODS; idx++) {
        const bypass_method_t *m = &bypass_methods[idx];
        if (!m->nodes || m->node_count == 0)
            continue;

        /* Probe: try writing enable values to all nodes.
         * Original sentinel logic: iVar5 = 0xff initially.
         * After each write: if write succeeded (ret==0) → iVar10=0,
         * else iVar10 = iVar5 (preserves non-zero sentinel).
         * Proceed only if final iVar10 == 0 (all writes succeeded). */
        int sentinel = 0xff;
        for (int i = 0; i < m->node_count; i++) {
            int ret = write_file_formatted(m->nodes[i].path, 0, 0,
                                           "%s", m->nodes[i].enable_value);
            int next = 0;
            if (ret != 0) {
                next = sentinel;
            }
            sentinel = next;
        }

        if (sentinel != 0)
            continue;  /* At least one sysfs node doesn't exist or isn't writable */

        printf("Testing switch '%s'...\n", m->name);
        sleep(BYPASS_TEST_WAIT_SEC);

        /* Take 15 current readings over 15 seconds */
        int total_ma = 0;
        for (int s = 0; s < BYPASS_TEST_SAMPLES; s++) {
            FILE *f = fopen(PATH_BATTERY_CURRENT, "r");
            uint32_t ma_val = 0;
            if (!f) {
                printf("Failed to read current: %s", strerror(errno));
            } else {
                char buf[32];
                char *ret = fgets(buf, 0x20, f);
                fclose(f);
                if (ret) {
                    int raw = atoi(buf);
                    uint32_t abs_val = (raw < 0) ? (uint32_t)(-raw) : (uint32_t)raw;
                    ma_val = abs_val / 1000;
                    if (g_current_ma_scale == 0) {
                        ma_val = abs_val;
                    }
                }
            }
            total_ma += (int)ma_val;
            printf("Current now: %d mA\n", (int)ma_val);
            sleep(1);
        }

        /* Restore: write disable_value to path for all nodes */
        for (int i = 0; i < m->node_count; i++) {
            write_file_formatted(m->nodes[i].path, 0, 0,
                                 "%s", m->nodes[i].disable_value);
        }

        float avg = (float)total_ma / 15.0f;
        printf("Avg current: %.2f mA\n", (double)avg);

        if (avg < BYPASS_TEST_THRESHOLD_MA) {
            printf("Switch '%s' is working (yay!!!)\n"
                   "Your device support bypass charging :)\n\n",
                   m->name);
            /* Save working method to config */
            write_file_formatted(PATH_NODE_CONFIG, 0, 0, "%s", m->name);
            exit(0);
        }

        printf("Switch '%s' is not working (boo!!!)\n", m->name);
    }

    puts("Your device does not support bypass charging :(");
    exit(1);
}
