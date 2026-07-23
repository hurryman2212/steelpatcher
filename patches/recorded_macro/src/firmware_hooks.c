#include <stddef.h>
#include <stdint.h>

#include "patch_runtime.h"

enum {
  kStagingBufferAddress = PATCH_STAGING_BUFFER_ADDRESS,
  kActivityAddress = PATCH_ACTIVITY_ADDRESS,
  kRawDriverAddress = PATCH_RAW_DRIVER_ADDRESS,
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

uint32_t FirmwareReadObject(uint32_t object_id, void *destination,
                            uint32_t size, uint32_t offset) {
  return ((GenericRead)kGenericReadAddress)(object_id, destination, size,
                                            offset);
}

uint32_t FirmwareWriteObject(uint32_t object_id, const void *source,
                             uint32_t size, uint32_t offset) {
  return ((GenericWrite)kGenericWriteAddress)(object_id, source, size, offset);
}

uint32_t FirmwareEraseObject(uint32_t object_id) {
  return ((GenericErase)kGenericEraseAddress)(object_id);
}

bool FirmwareEraseRawRange(uint32_t offset, uint32_t size) {
  volatile uintptr_t *raw_driver = (volatile uintptr_t *)kRawDriverAddress;
  void *raw_context = (void *)raw_driver[0];
  RawSectorErase raw_sector_erase = (RawSectorErase)kRawSectorEraseAddress;

  if (raw_context == NULL || (offset & 0xFFFu) != 0 || size == 0 ||
      (size & 0xFFFu) != 0) {
    return false;
  }
  while (size != 0) {
    raw_sector_erase(raw_context, offset);
    offset += 0x1000u;
    size -= 0x1000u;
  }
  return true;
}

uint8_t *FirmwareStagingBuffer(void) {
  return (uint8_t *)kStagingBufferAddress;
}

void FirmwareUpdateActivity(void) {
  volatile uint32_t *activity = (volatile uint32_t *)kActivityAddress;

  activity[3] = activity[0];
}
