#include <stdint.h>

#include "macro_engine.h"
#include "patch_runtime.h"

enum {
  kPatchLoaderFlagAddress = PATCH_LOADER_FLAG_ADDRESS,
};

static volatile uint32_t *const kPatchLoaderFlag =
    (volatile uint32_t *)kPatchLoaderFlagAddress;

static bool IsRangeValid(uint32_t offset, uint32_t size, uint32_t limit) {
  return size <= kStagingBufferSize && offset <= limit &&
         size <= limit - offset;
}

uint32_t PatchFlashEraseHandler(uint32_t unused_context, uint32_t unused_output,
                                const uint8_t *report) {
  uint16_t object_id;

  (void)unused_context;
  (void)unused_output;
  object_id = (uint16_t)report[2] | (uint16_t)((uint16_t)report[3] << 8);
  if (object_id == kMacroFileSystemId) {
    if (FirmwareEraseRawRange(kMacroRawOffset, kMacroSectorSize)) {
      PatchRuntimeInvalidateMacroCache();
    }
  } else if (object_id == kPatchUpdateFileSystemId) {
    FirmwareEraseRawRange(kPatchCodeRawOffset, kPatchCodeSectorSize);
    *kPatchLoaderFlag = 0;
  } else {
    FirmwareEraseObject(object_id);
  }
  FirmwareUpdateActivity();
  return 0;
}

uint32_t PatchFlashPushHandler(uint32_t unused_context, uint32_t unused_output,
                               const uint8_t *report) {
  uint32_t offset;
  uint32_t size;
  uint32_t write_succeeded;
  uint16_t object_id;

  (void)unused_context;
  (void)unused_output;
  object_id = (uint16_t)report[2] | (uint16_t)((uint16_t)report[3] << 8);
  offset = (uint32_t)report[4] | ((uint32_t)report[5] << 8) |
           ((uint32_t)report[6] << 16) | ((uint32_t)report[7] << 24);
  size = (uint32_t)report[8] | ((uint32_t)report[9] << 8);
  if (object_id == kMacroFileSystemId &&
      IsRangeValid(offset, size, kMacroDataSize)) {
    write_succeeded = FirmwareWriteObject(kRawObjectId, FirmwareStagingBuffer(),
                                          size, kMacroRawOffset + offset);
    if (write_succeeded != 0) {
      PatchRuntimeInvalidateMacroCache();
    }
  } else if (object_id == kPatchUpdateFileSystemId &&
             IsRangeValid(offset, size, kPatchCodeSectorSize)) {
    FirmwareWriteObject(kRawObjectId, FirmwareStagingBuffer(), size,
                        kPatchCodeRawOffset + offset);
    *kPatchLoaderFlag = 0;
  } else if ((object_id & 0xFF00u) == 0 && size <= kStagingBufferSize) {
    FirmwareWriteObject(object_id, FirmwareStagingBuffer(), size, offset);
  }
  FirmwareUpdateActivity();
  return 0;
}

uint32_t PatchFlashPullHandler(uint32_t unused_context, uint32_t unused_output,
                               const uint8_t *report) {
  uint32_t offset;
  uint32_t size;
  uint16_t object_id;

  (void)unused_context;
  (void)unused_output;
  object_id = (uint16_t)report[2] | (uint16_t)((uint16_t)report[3] << 8);
  offset = (uint32_t)report[4] | ((uint32_t)report[5] << 8) |
           ((uint32_t)report[6] << 16) | ((uint32_t)report[7] << 24);
  size = (uint32_t)report[8] | ((uint32_t)report[9] << 8);
  if (object_id == kMacroFileSystemId &&
      IsRangeValid(offset, size, kMacroDataSize)) {
    FirmwareReadObject(kRawObjectId, FirmwareStagingBuffer(), size,
                       kMacroRawOffset + offset);
  } else if (object_id == kPatchUpdateFileSystemId &&
             IsRangeValid(offset, size, kPatchCodeSectorSize)) {
    FirmwareReadObject(kRawObjectId, FirmwareStagingBuffer(), size,
                       kPatchCodeRawOffset + offset);
  } else if ((object_id & 0xFF00u) == 0 && size <= kStagingBufferSize) {
    FirmwareReadObject(object_id, FirmwareStagingBuffer(), size, offset);
  }
  FirmwareUpdateActivity();
  return 0;
}
