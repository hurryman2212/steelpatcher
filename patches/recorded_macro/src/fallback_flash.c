#include <stddef.h>
#include <stdint.h>

#include "patch_abi.h"
#include "target_config.h"

enum {
  kFlashEraseOperation = PATCH_ERASE_ENTRY_OFFSET,
  kFlashPushOperation = PATCH_PUSH_ENTRY_OFFSET,
  kFlashPullOperation = PATCH_PULL_ENTRY_OFFSET,
  kMacroFileSystemId = 0xFF20,
  kPatchUpdateFileSystemId = 0xFF21,
  kRawObjectId = 0,
  kMacroRawOffset = PATCH_MACRO_RAW_OFFSET,
  kMacroDataSize = PATCH_MACRO_DATA_SIZE,
  kPatchCodeRawOffset = PATCH_CODE_RAW_OFFSET,
  kPatchCodeSize = PATCH_CODE_SECTOR_SIZE,
  kMacroSectorSize = PATCH_MACRO_SECTOR_SIZE,
  kStagingBufferAddress = PATCH_STAGING_BUFFER_ADDRESS,
  kStagingBufferSize = PATCH_STAGING_BUFFER_SIZE,
  kActivityAddress = PATCH_ACTIVITY_ADDRESS,
  kRawDriverAddress = PATCH_RAW_DRIVER_ADDRESS,
  kPatchLoaderFlagAddress = PATCH_LOADER_FLAG_ADDRESS,
  kGenericReadAddress = 0x00021E05,
  kGenericWriteAddress = 0x00021E41,
  kGenericEraseAddress = 0x00021E7D,
  kRawSectorEraseAddress = 0x0001C2A5,
};

typedef uint32_t (*GenericRead)(uint32_t object_id, void *destination,
                                uint32_t size, uint32_t offset);
typedef uint32_t (*GenericWrite)(uint32_t object_id, const void *source,
                                 uint32_t size, uint32_t offset);
typedef uint32_t (*GenericErase)(uint32_t object_id);
typedef void (*RawSectorErase)(void *context, uint32_t offset);

uint32_t FallbackFlashHandler(uint32_t unused_context, uint32_t unused_output,
                              const uint8_t *report, uint32_t operation) {
  uint32_t range_limit;
  uint32_t raw_offset;
  uint32_t sector_size;
  uint32_t offset;
  uint32_t size;
  uint16_t object_id;

  (void)unused_context;
  (void)unused_output;
  object_id = (uint16_t)report[2] | (uint16_t)((uint16_t)report[3] << 8);
  offset = (uint32_t)report[4] | ((uint32_t)report[5] << 8) |
           ((uint32_t)report[6] << 16) | ((uint32_t)report[7] << 24);
  size = (uint32_t)report[8] | ((uint32_t)report[9] << 8);

  if (object_id == kMacroFileSystemId) {
    raw_offset = kMacroRawOffset;
    range_limit = kMacroDataSize;
    sector_size = kMacroSectorSize;
  } else if (object_id == kPatchUpdateFileSystemId) {
    raw_offset = kPatchCodeRawOffset;
    range_limit = kPatchCodeSize;
    sector_size = kPatchCodeSize;
  } else {
    if (operation == kFlashEraseOperation) {
      ((GenericErase)kGenericEraseAddress)(object_id);
    } else if ((object_id & 0xFF00u) == 0 && size <= kStagingBufferSize) {
      if (operation == kFlashPushOperation) {
        ((GenericWrite)kGenericWriteAddress)(
            object_id, (const void *)kStagingBufferAddress, size, offset);
      } else if (operation == kFlashPullOperation) {
        ((GenericRead)kGenericReadAddress)(
            object_id, (void *)kStagingBufferAddress, size, offset);
      }
    }
    goto update_activity;
  }

  if (operation == kFlashEraseOperation) {
    volatile uintptr_t *raw_driver = (volatile uintptr_t *)kRawDriverAddress;
    void *raw_context = (void *)raw_driver[0];
    RawSectorErase raw_sector_erase = (RawSectorErase)kRawSectorEraseAddress;

    if (raw_context != NULL && (raw_offset & 0xFFFu) == 0 &&
        (sector_size & 0xFFFu) == 0) {
      while (sector_size != 0) {
        raw_sector_erase(raw_context, raw_offset);
        raw_offset += 0x1000u;
        sector_size -= 0x1000u;
      }
    }
  } else if (size <= kStagingBufferSize && offset <= range_limit &&
             size <= range_limit - offset) {
    if (operation == kFlashPushOperation) {
      ((GenericWrite)kGenericWriteAddress)(kRawObjectId,
                                           (const void *)kStagingBufferAddress,
                                           size, raw_offset + offset);
    } else if (operation == kFlashPullOperation) {
      ((GenericRead)kGenericReadAddress)(kRawObjectId,
                                         (void *)kStagingBufferAddress, size,
                                         raw_offset + offset);
    }
  }
  if (object_id == kPatchUpdateFileSystemId &&
      (operation == kFlashEraseOperation || operation == kFlashPushOperation)) {
    *(volatile uint32_t *)kPatchLoaderFlagAddress = 0;
  }

update_activity:
  ((volatile uint32_t *)kActivityAddress)[3] =
      ((volatile uint32_t *)kActivityAddress)[0];
  return 0;
}
