.syntax unified
.cpu cortex-m4
.thumb

#include "patch_abi.h"
#include "target_config.h"

.equ PATCH_MAGIC, 0x504d3352
.equ GENERIC_READ_ADDRESS, 0x00021e05
.equ CRC32_ADDRESS, 0x0001c04b
.equ FALLBACK_FLASH_HANDLER_ADDRESS, 0x0002ab2d

.section .text.EnsurePatchLoaded, "ax", %progbits
.type EnsurePatchLoaded, %function
.thumb_func
EnsurePatchLoaded:
    push {r4, lr}
    ldr r4, =PATCH_LOADER_FLAG_ADDRESS
    ldr r3, [r4]
    ldr r2, =PATCH_MAGIC
    cmp r3, r2
    beq .Lloaded
    cmp r3, #0
    bne .Lload_failed
    movs r3, #1
    str r3, [r4]
    movs r0, #0
    ldr r1, =PATCH_CODE_ADDRESS
    mov.w r2, #PATCH_LOAD_SIZE
    ldr r3, =PATCH_CODE_RAW_OFFSET
    ldr r12, =GENERIC_READ_ADDRESS
    blx r12
    cbz r0, .Lread_failed
    dsb sy
    ldr r0, =PATCH_CODE_ADDRESS
    mov.w r1, #PATCH_LOAD_SIZE
    movs r2, #0
    ldr r3, =CRC32_ADDRESS
    blx r3
    cmn r0, #1
    bne .Linvalidate
    ldr r3, =PATCH_CODE_ADDRESS
    ldr r0, [r3]
    ldr r1, =PATCH_MAGIC
    cmp r0, r1
    bne .Linvalidate
    ldr r0, [r3, #4]
    ldr r1, =PATCH_HEADER_ABI
    cmp r0, r1
    bne .Linvalidate
    ldr r0, [r3, #0x08]
    cmp r0, r3
    bne .Linvalidate
    ldr r0, [r3, #0x24]
    ldr r1, =PATCH_CODE_RAW_OFFSET
    cmp r0, r1
    bne .Linvalidate
    ldr r0, =PATCH_MAGIC
    str r0, [r4]
    dsb sy
    isb sy
.Lloaded:
    movs r0, #1
    pop {r4, pc}
.Linvalidate:
    movs r3, #2
    b .Lclear_invalid_image
.Lread_failed:
    movs r3, #0
.Lclear_invalid_image:
    str r3, [r4]
    movs r3, #0
    ldr r2, =PATCH_CODE_ADDRESS
    str r3, [r2]
.Lload_failed:
    movs r0, #0
    pop {r4, pc}
.size EnsurePatchLoaded, . - EnsurePatchLoaded

.section .text.DispatchPatchEntry, "ax", %progbits
.type DispatchPatchEntry, %function
.thumb_func
DispatchPatchEntry:
    stmdb sp!, {r0-r3, r12, lr}
    bl EnsurePatchLoaded
    str r0, [sp, #16]
    ldmia sp!, {r0-r3, r12, lr}
    cmp r12, #0
    beq .Ldispatch_failed
    ldr r12, =PATCH_CODE_ADDRESS
    ldr r3, [r12, r3]
    bx r3
.Ldispatch_failed:
    cmp r3, #PATCH_ERASE_ENTRY_OFFSET
    blo .Ldispatch_noop
    ldr r12, =FALLBACK_FLASH_HANDLER_ADDRESS
    bx r12
.Ldispatch_noop:
    movs r0, #0
    bx lr
.size DispatchPatchEntry, . - DispatchPatchEntry

.section .text.PatchMappingPressTrampoline, "ax", %progbits
.global PatchMappingPressTrampoline
.type PatchMappingPressTrampoline, %function
.thumb_func
PatchMappingPressTrampoline:
    ldrb r3, [r2]
    cmp r3, #0x71
    beq .Lmacro_press
    cmp r3, #0x32
    ldr pc, =0x00020c15
.Lmacro_press:
    mov r0, r1
    mov r1, r2
    movs r3, #PATCH_PRESS_ENTRY_OFFSET
    b DispatchPatchEntry
.size PatchMappingPressTrampoline, . - PatchMappingPressTrampoline

.section .text.PatchMappingReleaseTrampoline, "ax", %progbits
.global PatchMappingReleaseTrampoline
.type PatchMappingReleaseTrampoline, %function
.thumb_func
PatchMappingReleaseTrampoline:
    ldrb r3, [r1]
    cmp r3, #0x71
    beq .Lmacro_release
    cmp r3, #0x34
    ldr pc, =0x00020c7d
.Lmacro_release:
    movs r3, #PATCH_RELEASE_ENTRY_OFFSET
    b DispatchPatchEntry
.size PatchMappingReleaseTrampoline, . - PatchMappingReleaseTrampoline

.section .text.PatchTickTrampoline, "ax", %progbits
.global PatchTickTrampoline
.type PatchTickTrampoline, %function
.thumb_func
PatchTickTrampoline:
    movs r3, #0
    strb r3, [r4, #0x0a]
    bl EnsurePatchLoaded
    cbz r0, .Ltick_done
    ldr r3, =PATCH_CODE_ADDRESS
    ldr r3, [r3, #PATCH_TICK_ENTRY_OFFSET]
    blx r3
    cbz r0, .Ltick_done
    ldr r3, =PATCH_TICK_OUTPUT_ADDRESS
    strb r0, [r3]
.Ltick_done:
    ldr pc, =0x0001edad
.size PatchTickTrampoline, . - PatchTickTrampoline

.section .text.PatchFlashTrampolines, "ax", %progbits
.global PatchFlashEraseTrampoline
.type PatchFlashEraseTrampoline, %function
.thumb_func
PatchFlashEraseTrampoline:
    movs r3, #PATCH_ERASE_ENTRY_OFFSET
    b DispatchPatchEntry
.size PatchFlashEraseTrampoline, . - PatchFlashEraseTrampoline

.global PatchFlashPushTrampoline
.type PatchFlashPushTrampoline, %function
.thumb_func
PatchFlashPushTrampoline:
    movs r3, #PATCH_PUSH_ENTRY_OFFSET
    b DispatchPatchEntry
.size PatchFlashPushTrampoline, . - PatchFlashPushTrampoline

.global PatchFlashPullTrampoline
.type PatchFlashPullTrampoline, %function
.thumb_func
PatchFlashPullTrampoline:
    movs r3, #PATCH_PULL_ENTRY_OFFSET
    b DispatchPatchEntry
.size PatchFlashPullTrampoline, . - PatchFlashPullTrampoline
