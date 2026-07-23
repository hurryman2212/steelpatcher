#ifndef STEELPATCHER_RECORDED_MACRO_TARGET_CONFIG_H_
#define STEELPATCHER_RECORDED_MACRO_TARGET_CONFIG_H_

#if !defined(PATCH_CODE_ADDRESS) || !defined(PATCH_CODE_RAW_OFFSET) ||         \
    !defined(PATCH_LOAD_SIZE) || !defined(PATCH_CODE_SECTOR_SIZE) ||           \
    !defined(PATCH_MACRO_RAW_OFFSET) || !defined(PATCH_MACRO_SECTOR_SIZE) ||   \
    !defined(PATCH_MACRO_DATA_SIZE) || !defined(PATCH_STATE_ADDRESS) ||        \
    !defined(PATCH_STATE_LIMIT) || !defined(PATCH_LOADER_FLAG_ADDRESS) ||      \
    !defined(PATCH_TARGET_OUTPUT_ADDRESS) ||                                   \
    !defined(PATCH_MOUSE_REPORT_BUTTONS_ADDRESS) ||                            \
    !defined(PATCH_MOUSE_REPORT_PREVIOUS_BUTTONS_ADDRESS) ||                   \
    !defined(PATCH_TICK_OUTPUT_ADDRESS) ||                                     \
    !defined(PATCH_STAGING_BUFFER_ADDRESS) ||                                  \
    !defined(PATCH_STAGING_BUFFER_SIZE) || !defined(PATCH_ACTIVITY_ADDRESS) || \
    !defined(PATCH_RAW_DRIVER_ADDRESS)
#error "recorded_macro target configuration is incomplete"
#endif

#endif
