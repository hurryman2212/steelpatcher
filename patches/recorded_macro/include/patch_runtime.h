#ifndef STEELPATCHER_RECORDED_MACRO_PATCH_RUNTIME_H_
#define STEELPATCHER_RECORDED_MACRO_PATCH_RUNTIME_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "target_config.h"

enum {
  kPatchCodeAddress = PATCH_CODE_ADDRESS,
  kPatchCodeRawOffset = PATCH_CODE_RAW_OFFSET,
  kPatchLoadSize = PATCH_LOAD_SIZE,
  kPatchCodeSectorSize = PATCH_CODE_SECTOR_SIZE,
  kMacroRawOffset = PATCH_MACRO_RAW_OFFSET,
  kMacroSectorSize = PATCH_MACRO_SECTOR_SIZE,
  kMacroFileSystemId = 0xFF20,
  kPatchUpdateFileSystemId = 0xFF21,
  kRawObjectId = 0,
  kStagingBufferSize = PATCH_STAGING_BUFFER_SIZE,
};

uint32_t FirmwareReadObject(uint32_t object_id, void *destination,
                            uint32_t size, uint32_t offset);
uint32_t FirmwareWriteObject(uint32_t object_id, const void *source,
                             uint32_t size, uint32_t offset);
uint32_t FirmwareEraseObject(uint32_t object_id);
bool FirmwareEraseRawRange(uint32_t offset, uint32_t size);
uint8_t *FirmwareStagingBuffer(void);
void FirmwareUpdateActivity(void);

void PatchRuntimeInvalidateMacroCache(void);
void PatchMacroTriggerPress(uint32_t source_id, const uint8_t mapping[5]);
void PatchMacroTriggerRelease(uint32_t source_id, const uint8_t mapping[5]);
bool PatchMacroTick(void);
uint32_t PatchFlashEraseHandler(uint32_t unused_context, uint32_t unused_output,
                                const uint8_t *report);
uint32_t PatchFlashPushHandler(uint32_t unused_context, uint32_t unused_output,
                               const uint8_t *report);
uint32_t PatchFlashPullHandler(uint32_t unused_context, uint32_t unused_output,
                               const uint8_t *report);

#endif
