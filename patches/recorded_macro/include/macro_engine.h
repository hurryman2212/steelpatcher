#ifndef RIVAL3WL_RECORDED_MACRO_MACRO_ENGINE_H_
#define RIVAL3WL_RECORDED_MACRO_MACRO_ENGINE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
  kMacroDataSize = 1280,
  kMacroSlotCount = 4,
  kMacroKeyboardBitmapSize = 32,
  kMacroMediaKeyCount = 4,
  kMacroMappingFunction = 0x71,
};

typedef struct {
  uint16_t start_word;
  uint16_t current_word;
  uint16_t end_word;
  uint16_t event_delay;
  uint16_t repeat_delay;
  uint16_t repeat_wait;
  uint32_t source_id;
  uint8_t playback_type;
  uint8_t direction;
  uint8_t remaining_repeats;
  uint8_t pressed;
  uint8_t toggled;
  uint8_t holding;
  uint8_t active;
  uint8_t mouse_buttons;
  uint8_t keyboard[kMacroKeyboardBitmapSize];
  uint8_t media[kMacroMediaKeyCount];
} MacroSlot;

_Static_assert(sizeof(MacroSlot) == 60,
               "macro slot must match the reviewed 60-byte layout");

typedef bool (*MacroDataReader)(void *context, uint32_t offset,
                                uint8_t *destination, size_t size);

typedef struct {
  MacroDataReader read_data;
  void *read_context;
  MacroSlot slots[kMacroSlotCount];
} MacroEngine;

typedef struct {
  uint32_t mouse_buttons;
  int32_t vertical_wheel;
  int32_t horizontal_wheel;
  uint8_t keyboard[kMacroKeyboardBitmapSize];
  uint8_t media[kMacroMediaKeyCount];
} MacroOutput;

void MacroEngineInitialize(MacroEngine *engine, MacroDataReader read_data,
                           void *read_context);
void MacroEngineTrigger(MacroEngine *engine, uint32_t source_id,
                        const uint8_t mapping[5], bool pressed);
bool MacroEngineTick(MacroEngine *engine, MacroOutput *output);

#endif
