# Recorded macro patch

## Binary binding placeholder baseline

The `bindings` placeholder values were linked against the SteelSeries
Rival 3 Wireless Gen 2 mouse MCU firmware v1.5.0.0:

```text
SHA-256: b2546a383d9f35516041b8844c3b04df0231db801fd4e7384bc39e601cb9ce38
```

Addresses that refer to Thumb code include the Thumb bit. The placeholders are
location markers, not fixed compatibility addresses. Before producing a patched
image, `steelpatcher` resolves and validates each binding against the target
firmware and writes the resolved address into every declared placeholder slot.
