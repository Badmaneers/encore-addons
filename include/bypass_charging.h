/**
 * bypass_charging.h — Bypass charging hardware detection and control
 */

#ifndef ENCORE_BYPASS_CHARGING_H
#define ENCORE_BYPASS_CHARGING_H

#include "common.h"

/**
 * Read the bypass charging method name from the node_part config file.
 * Returns the method index (0..MAX_BYPASS_METHODS-1) or -1 on error.
 */
int read_node_config(void);

/**
 * Run the bypass charging hardware test (--test mode).
 * Iterates through all known bypass methods, writes sysfs nodes,
 * measures battery current, and saves the working method to config.
 * Exits the process on completion.
 */
void run_bypass_test(void);

/**
 * Enable bypass charging using the given method index.
 * Writes "enable" values to all sysfs nodes for that method.
 */
void bypass_enable(int method_index);

/**
 * Disable bypass charging using the given method index.
 * Writes "disable" values to all sysfs nodes for that method.
 */
void bypass_disable(int method_index);

/**
 * Read the current battery current in mA.
 * Reads from /sys/class/power_supply/battery/current_now.
 * Returns the absolute value in mA (handles µA vs mA scaling).
 * Returns -1 on error.
 */
int read_battery_current_ma(void);

/**
 * Get the bypass method table (compiled-in list of known methods).
 */
const bypass_method_t *get_bypass_methods(void);

#endif /* ENCORE_BYPASS_CHARGING_H */
