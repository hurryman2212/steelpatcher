#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "macro_engine.h"
#include "patch_abi.h"
#include "patch_runtime.h"

enum {
  kPatchHeaderMagic = 0x504D3352,
  kPatchStateAddress = PATCH_STATE_ADDRESS,
  kPatchStateLimit = PATCH_STATE_LIMIT,
  kPatchLoaderFlagAddress = PATCH_LOADER_FLAG_ADDRESS,
  kTargetOutputAddress = PATCH_TARGET_OUTPUT_ADDRESS,
  kMouseReportButtonsAddress = PATCH_MOUSE_REPORT_BUTTONS_ADDRESS,
  kMouseReportPreviousButtonsAddress =
      PATCH_MOUSE_REPORT_PREVIOUS_BUTTONS_ADDRESS,
};

typedef struct {
  MacroEngine engine;
  uint8_t macro_data[kMacroDataSize];
  uint32_t previous_mouse_buttons;
} PatchState;

typedef struct {
  uint32_t magic;
  uint16_t header_size;
  uint16_t abi_version;
  uint32_t code_address;
  uint32_t load_size;
  uint32_t macro_raw_offset;
  uint32_t macro_data_size;
  uint32_t macro_sector_size;
  uint32_t state_address;
  uint32_t state_limit;
  uint32_t code_raw_offset;
  uint32_t code_sector_size;
  uintptr_t press_entry;
  uintptr_t release_entry;
  uintptr_t tick_entry;
  uintptr_t erase_entry;
  uintptr_t push_entry;
  uintptr_t pull_entry;
  uint32_t image_crc32_residue;
} PatchImageHeader;

_Static_assert(sizeof(PatchImageHeader) == PATCH_HEADER_SIZE,
               "patch header must remain exactly 72 bytes");
_Static_assert(offsetof(PatchImageHeader, press_entry) ==
                   PATCH_PRESS_ENTRY_OFFSET,
               "press entry offset must match the loader ABI");
_Static_assert(offsetof(PatchImageHeader, release_entry) ==
                   PATCH_RELEASE_ENTRY_OFFSET,
               "release entry offset must match the loader ABI");
_Static_assert(offsetof(PatchImageHeader, tick_entry) ==
                   PATCH_TICK_ENTRY_OFFSET,
               "tick entry offset must match the loader ABI");
_Static_assert(offsetof(PatchImageHeader, erase_entry) ==
                   PATCH_ERASE_ENTRY_OFFSET,
               "erase entry offset must match the loader ABI");
_Static_assert(offsetof(PatchImageHeader, push_entry) ==
                   PATCH_PUSH_ENTRY_OFFSET,
               "push entry offset must match the loader ABI");
_Static_assert(offsetof(PatchImageHeader, pull_entry) ==
                   PATCH_PULL_ENTRY_OFFSET,
               "pull entry offset must match the loader ABI");
_Static_assert(sizeof(PatchState) ==
                   kPatchLoaderFlagAddress - kPatchStateAddress,
               "patch state must exactly fill the reviewed RAM reservation");
_Static_assert(offsetof(PatchState, macro_data) == sizeof(MacroEngine),
               "macro cache must immediately follow the macro engine");
_Static_assert(offsetof(PatchState, previous_mouse_buttons) +
                       sizeof(uint32_t) ==
                   sizeof(PatchState),
               "mouse output state must end the patch state reservation");
_Static_assert(kPatchLoaderFlagAddress + sizeof(uint32_t) == kPatchStateLimit,
               "loader flag must end at the reviewed BSS limit");
_Static_assert(kPatchCodeRawOffset % kPatchCodeSectorSize == 0,
               "patch code must be sector aligned");
_Static_assert(kPatchCodeRawOffset != kMacroRawOffset,
               "patch code must not overlap macro storage");

__attribute__((used, section(".patch_header"))) static const PatchImageHeader
    kPatchImageHeader = {
        .magic = kPatchHeaderMagic,
        .header_size = sizeof(PatchImageHeader),
        .abi_version = PATCH_ABI_VERSION,
        .code_address = kPatchCodeAddress,
        .load_size = kPatchLoadSize,
        .macro_raw_offset = kMacroRawOffset,
        .macro_data_size = kMacroDataSize,
        .macro_sector_size = kMacroSectorSize,
        .state_address = kPatchStateAddress,
        .state_limit = kPatchStateLimit,
        .code_raw_offset = kPatchCodeRawOffset,
        .code_sector_size = kPatchCodeSectorSize,
        .press_entry = (uintptr_t)PatchMacroTriggerPress,
        .release_entry = (uintptr_t)PatchMacroTriggerRelease,
        .tick_entry = (uintptr_t)PatchMacroTick,
        .erase_entry = (uintptr_t)PatchFlashEraseHandler,
        .push_entry = (uintptr_t)PatchFlashPushHandler,
        .pull_entry = (uintptr_t)PatchFlashPullHandler,
        .image_crc32_residue = 0xFFFFFFFF,
};

static PatchState *const kPatchState = (PatchState *)kPatchStateAddress;
static volatile uint8_t *const kTargetOutput =
    (volatile uint8_t *)kTargetOutputAddress;
static volatile uint8_t *const kMouseReportButtons =
    (volatile uint8_t *)kMouseReportButtonsAddress;
static volatile uint8_t *const kMouseReportPreviousButtons =
    (volatile uint8_t *)kMouseReportPreviousButtonsAddress;
static bool ReadMacroCache(void *context, uint32_t offset, uint8_t *destination,
                           size_t size) {
  const uint8_t *source;
  size_t index;

  if (offset > kMacroDataSize || size > kMacroDataSize - offset) {
    return false;
  }
  source = (const uint8_t *)context + offset;
  for (index = 0; index < size; ++index) {
    destination[index] = source[index];
  }
  return true;
}

static bool EnsureInitialized(void) {
  if (kPatchState->engine.read_data == ReadMacroCache &&
      kPatchState->engine.read_context == kPatchState->macro_data) {
    return true;
  }
  if (FirmwareReadObject(kRawObjectId, kPatchState->macro_data, kMacroDataSize,
                         kMacroRawOffset) == 0) {
    return false;
  }
  MacroEngineInitialize(&kPatchState->engine, ReadMacroCache,
                        kPatchState->macro_data);
  kPatchState->previous_mouse_buttons = 0;
  return true;
}

static void MergeMedia(const MacroOutput *output) {
  size_t input_index;
  size_t output_index;

  output_index = 0;
  while (output_index < kMacroMediaKeyCount &&
         kTargetOutput[0x28 + output_index] != 0) {
    ++output_index;
  }
  for (input_index = 0; input_index < kMacroMediaKeyCount; ++input_index) {
    if (output->media[input_index] == 0) {
      continue;
    }
    if (output_index == kMacroMediaKeyCount) {
      return;
    }
    kTargetOutput[0x28 + output_index] = output->media[input_index];
    ++output_index;
  }
}

void PatchMacroTriggerPress(uint32_t source_id, const uint8_t mapping[5]) {
  if (EnsureInitialized()) {
    MacroEngineTrigger(&kPatchState->engine, source_id, mapping, true);
  }
}

void PatchMacroTriggerRelease(uint32_t source_id, const uint8_t mapping[5]) {
  if (EnsureInitialized()) {
    MacroEngineTrigger(&kPatchState->engine, source_id, mapping, false);
  }
}

bool PatchMacroTick(void) {
  MacroOutput output;
  bool should_reschedule;
  uint8_t mouse_buttons;
  size_t index;

  if (!EnsureInitialized()) {
    return false;
  }
  should_reschedule = MacroEngineTick(&kPatchState->engine, &output);
  mouse_buttons = (uint8_t)output.mouse_buttons;
  if ((uint8_t)kPatchState->previous_mouse_buttons != mouse_buttons) {
    kPatchState->previous_mouse_buttons = mouse_buttons;
    *kMouseReportPreviousButtons = (uint8_t)(mouse_buttons ^ 0x80u);
  }
  *kMouseReportButtons = mouse_buttons;
  *(volatile int8_t *)(kTargetOutput + 0x04) += (int8_t)output.vertical_wheel;
  for (index = 0; index < kMacroKeyboardBitmapSize; ++index) {
    kTargetOutput[0x08 + index] |= output.keyboard[index];
  }
  MergeMedia(&output);
  *(volatile int32_t *)(kTargetOutput + 0x30) += output.horizontal_wheel;
  return should_reschedule;
}

void PatchRuntimeInvalidateMacroCache(void) {
  kPatchState->engine.read_data = NULL;
}
