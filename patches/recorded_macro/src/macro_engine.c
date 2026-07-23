#include "macro_engine.h"

enum {
  kMacroMagic = 0x77,
  kMacroHeaderSize = 8,
  kMacroEventSize = 4,
  kPlaybackPlayOnce = 1,
  kPlaybackRepeatCount = 2,
  kPlaybackRepeatWhilePressed = 3,
  kPlaybackToggleRepeat = 4,
  kPlaybackToggleHold = 5,
  kEventMouseButton = 0,
  kEventVerticalWheel = 1,
  kEventKeyboard = 2,
  kEventDelay = 4,
  kEventHorizontalWheel = 12,
  kKeyboardUsagePage = 1,
  kConsumerUsagePage = 12,
  kTargetMouseButtonMask = 0x3F,
};

static uint16_t ReadLe16(const uint8_t *bytes) {
  return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8);
}

static void ClearBytes(uint8_t *bytes, size_t size) {
  size_t index;

  for (index = 0; index < size; ++index) {
    bytes[index] = 0;
  }
}

static void ClearSlotOutput(MacroSlot *slot) {
  slot->mouse_buttons = 0;
  ClearBytes(slot->keyboard, sizeof(slot->keyboard));
  ClearBytes(slot->media, sizeof(slot->media));
}

static void StopSlot(MacroSlot *slot) {
  ClearBytes((uint8_t *)slot, sizeof(*slot));
}

static bool IsEventValid(const uint8_t event[kMacroEventSize]) {
  if (event[0] == kEventMouseButton) {
    return event[3] <= 1 && (event[1] & (uint8_t)~kTargetMouseButtonMask) == 0;
  }
  if (event[0] == kEventVerticalWheel || event[0] == kEventDelay ||
      event[0] == kEventHorizontalWheel) {
    return true;
  }
  return event[0] == kEventKeyboard && event[3] <= 1 &&
         (event[2] == kKeyboardUsagePage || event[2] == kConsumerUsagePage);
}

static bool ReadMacroData(const MacroEngine *engine, uint32_t offset,
                          uint8_t *destination, size_t size) {
  return engine->read_data != NULL && offset <= kMacroDataSize &&
         size <= kMacroDataSize - offset &&
         engine->read_data(engine->read_context, offset, destination, size);
}

static bool ReadMacroHeader(const MacroEngine *engine, uint16_t header_word,
                            uint8_t header[kMacroHeaderSize]) {
  uint16_t event_count;
  uint16_t first_event_word;
  uint16_t word_count;

  word_count = kMacroDataSize / kMacroEventSize;
  if (header_word > word_count - (kMacroHeaderSize / kMacroEventSize)) {
    return false;
  }

  if (!ReadMacroData(engine, (uint32_t)header_word * kMacroEventSize, header,
                     kMacroHeaderSize)) {
    return false;
  }
  event_count = ReadLe16(header + 2);
  first_event_word = header_word + (kMacroHeaderSize / kMacroEventSize);
  if (header[0] != kMacroMagic || header[1] < kPlaybackPlayOnce ||
      header[1] > kPlaybackToggleHold || header[4] > 1 || event_count == 0 ||
      (header[1] == kPlaybackRepeatCount && header[5] == 0) ||
      event_count > word_count - first_event_word) {
    return false;
  }
  return true;
}

static MacroSlot *FindSlot(MacroEngine *engine, uint32_t source_id) {
  size_t index;

  for (index = 0; index < kMacroSlotCount; ++index) {
    if (engine->slots[index].active != 0 &&
        engine->slots[index].source_id == source_id) {
      return &engine->slots[index];
    }
  }
  return NULL;
}

static MacroSlot *FindFreeSlot(MacroEngine *engine) {
  MacroSlot *free_slot;
  size_t index;

  free_slot = NULL;
  for (index = 0; index < kMacroSlotCount; ++index) {
    if (engine->slots[index].active == 0) {
      free_slot = &engine->slots[index];
    }
  }
  return free_slot;
}

static void InitializeSlot(MacroSlot *slot, const uint8_t *header,
                           uint32_t source_id, uint16_t header_word,
                           bool pressed) {
  uint16_t event_count;

  event_count = ReadLe16(header + 2);
  StopSlot(slot);
  slot->start_word = header_word + (kMacroHeaderSize / kMacroEventSize);
  slot->current_word = slot->start_word;
  slot->end_word = slot->start_word + event_count;
  slot->repeat_delay = ReadLe16(header + 6);
  slot->source_id = source_id;
  slot->playback_type = header[1];
  slot->direction = header[4];
  slot->remaining_repeats = header[5];
  slot->pressed = pressed ? 1 : 0;
  slot->toggled = 1;
  slot->active = 1;
}

static void SetKeyboardState(MacroSlot *slot, uint8_t usage, bool pressed) {
  uint8_t mask;
  uint8_t *byte;

  byte = &slot->keyboard[usage >> 3];
  mask = (uint8_t)(1u << (usage & 7));
  if (pressed) {
    *byte |= mask;
  } else {
    *byte &= (uint8_t)~mask;
  }
}

static void SetMediaState(MacroSlot *slot, uint8_t usage, bool pressed) {
  size_t index;
  size_t found_index;

  found_index = kMacroMediaKeyCount;
  for (index = 0; index < kMacroMediaKeyCount; ++index) {
    if (slot->media[index] == usage) {
      found_index = index;
      break;
    }
  }

  if (!pressed) {
    if (found_index < kMacroMediaKeyCount) {
      for (index = found_index; index + 1 < kMacroMediaKeyCount; ++index) {
        slot->media[index] = slot->media[index + 1];
      }
      slot->media[kMacroMediaKeyCount - 1] = 0;
    }
    return;
  }

  for (index = 0; index < kMacroMediaKeyCount; ++index) {
    if (slot->media[index] == 0) {
      slot->media[index] = usage;
      return;
    }
  }
}

static void ExecuteEvent(MacroSlot *slot, const uint8_t event[kMacroEventSize],
                         MacroOutput *output) {
  if (event[0] == kEventMouseButton) {
    if (event[3] == 0) {
      slot->mouse_buttons &= (uint8_t)~event[1];
    } else if (event[3] == 1) {
      slot->mouse_buttons |= event[1];
    }
  } else if (event[0] == kEventVerticalWheel) {
    output->vertical_wheel += (int8_t)event[3];
  } else if (event[0] == kEventKeyboard) {
    if (event[2] == kKeyboardUsagePage) {
      SetKeyboardState(slot, event[1], event[3] != 0);
    } else if (event[2] == kConsumerUsagePage) {
      SetMediaState(slot, event[1], event[3] != 0);
    }
  } else if (event[0] == kEventDelay) {
    slot->event_delay = ReadLe16(event + 2);
  } else if (event[0] == kEventHorizontalWheel) {
    output->horizontal_wheel += (int8_t)event[3];
  }
}

static bool RestartOrStop(MacroSlot *slot) {
  bool restart;

  restart = false;
  if (slot->playback_type == kPlaybackRepeatCount) {
    --slot->remaining_repeats;
    restart = slot->remaining_repeats != 0;
  } else if (slot->playback_type == kPlaybackRepeatWhilePressed) {
    restart = slot->pressed != 0;
  } else if (slot->playback_type == kPlaybackToggleRepeat) {
    restart = slot->toggled != 0;
  } else if (slot->playback_type == kPlaybackToggleHold) {
    if (slot->toggled != 0) {
      slot->holding = 1;
      return true;
    }
  }

  if (!restart) {
    StopSlot(slot);
    return false;
  }
  slot->current_word = slot->start_word;
  slot->event_delay = 0;
  slot->repeat_wait = slot->repeat_delay;
  ClearSlotOutput(slot);
  return true;
}

static bool ShouldStopHolding(const MacroSlot *slot) {
  return slot->playback_type == kPlaybackToggleHold && slot->toggled == 0;
}

static bool ShouldStopRepeatWait(const MacroSlot *slot) {
  return (slot->playback_type == kPlaybackRepeatWhilePressed &&
          slot->pressed == 0) ||
         (slot->playback_type == kPlaybackToggleRepeat && slot->toggled == 0);
}

static void MergeMedia(const MacroSlot *slot, MacroOutput *output) {
  size_t input_index;
  size_t output_index;

  output_index = 0;
  while (output_index < kMacroMediaKeyCount &&
         output->media[output_index] != 0) {
    ++output_index;
  }
  for (input_index = 0; input_index < kMacroMediaKeyCount; ++input_index) {
    if (slot->media[input_index] == 0) {
      continue;
    }
    if (output_index == kMacroMediaKeyCount) {
      return;
    }
    output->media[output_index] = slot->media[input_index];
    ++output_index;
  }
}

static void MergeSlot(const MacroSlot *slot, MacroOutput *output) {
  size_t index;

  output->mouse_buttons |= slot->mouse_buttons;
  for (index = 0; index < kMacroKeyboardBitmapSize; ++index) {
    output->keyboard[index] |= slot->keyboard[index];
  }
  MergeMedia(slot, output);
}

void MacroEngineInitialize(MacroEngine *engine, MacroDataReader read_data,
                           void *read_context) {
  ClearBytes((uint8_t *)engine, sizeof(*engine));
  engine->read_data = read_data;
  engine->read_context = read_context;
}

void MacroEngineTrigger(MacroEngine *engine, uint32_t source_id,
                        const uint8_t mapping[5], bool pressed) {
  MacroSlot *slot;
  uint8_t header[kMacroHeaderSize];
  uint16_t header_word;

  if (mapping[0] != kMacroMappingFunction) {
    return;
  }

  slot = FindSlot(engine, source_id);
  if (slot != NULL) {
    slot->pressed = pressed ? 1 : 0;
    if (slot->direction == (pressed ? 1 : 0)) {
      slot->toggled ^= 1;
    }
    return;
  }

  header_word = ReadLe16(mapping + 3);
  if (!ReadMacroHeader(engine, header_word, header)) {
    return;
  }
  if (header[4] != (pressed ? 1 : 0)) {
    return;
  }
  slot = FindFreeSlot(engine);
  if (slot != NULL) {
    InitializeSlot(slot, header, source_id, header_word, pressed);
  }
}

bool MacroEngineTick(MacroEngine *engine, MacroOutput *output) {
  MacroSlot *slot;
  uint8_t event[kMacroEventSize];
  bool had_active_slot;
  size_t index;

  had_active_slot = false;
  ClearBytes((uint8_t *)output, sizeof(*output));
  for (index = 0; index < kMacroSlotCount; ++index) {
    slot = &engine->slots[index];
    if (slot->active == 0) {
      continue;
    }
    had_active_slot = true;
    if (slot->holding != 0) {
      if (ShouldStopHolding(slot)) {
        StopSlot(slot);
      } else {
        MergeSlot(slot, output);
      }
      continue;
    }
    if (slot->repeat_wait != 0) {
      --slot->repeat_wait;
      if (ShouldStopRepeatWait(slot)) {
        StopSlot(slot);
      } else {
        MergeSlot(slot, output);
      }
      continue;
    }
    if (slot->event_delay != 0) {
      --slot->event_delay;
      MergeSlot(slot, output);
      continue;
    }
    if (slot->current_word == slot->end_word) {
      if (RestartOrStop(slot)) {
        MergeSlot(slot, output);
      }
      continue;
    }

    if (!ReadMacroData(engine, (uint32_t)slot->current_word * kMacroEventSize,
                       event, sizeof(event)) ||
        !IsEventValid(event)) {
      StopSlot(slot);
      continue;
    }
    ExecuteEvent(slot, event, output);
    ++slot->current_word;
    MergeSlot(slot, output);
  }
  return had_active_slot;
}
