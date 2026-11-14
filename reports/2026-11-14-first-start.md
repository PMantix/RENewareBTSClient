# 2026-11-14 First start from our code (62-1-1, test_rest.xml)

## Setup
- Channel 62-1-1 (no cell, allowlisted), idle before the start; user approved
  ("go ahead for test_rest") and watched the GUI.
- `python tools/start_test.py 62-1-1 tests/data/test_rest.xml --send` (btsmon.start,
  commit 7a93026). Full log: `logs/start_20261114_073236_62-1-1.log` (git-ignored).

## What was run
The 8-stage CmdStart83 transaction built from decompiled code: Map, Barcode, Remark,
Step (1 chunk, 3 steps, 137 B), StepGlobal, GlobalPrt, Start, StartConfirm.

## Results
- Every stage answered result 0 within ~140 ms in total (07:32:36.586 - .724).
- Start reply: test id 142 for unit 1 chl 1; confirm sent with it, confirm result 0.
- Live feed 5 s later: working, step 1 (rest), test_id 142.
- Server StartInfo log: the h_test row for 142 has the same shape as the GUI's test 141
  (step_name test_rest.xml, batch_no = start time, rng_cur 50) and the logged step rows
  (3 steps + type-254 global record) are identical to test 141's.

## New facts
- F-START-5 now Observed: all request layouts accepted by BtsServer 8.0.1.437.
- Reply layouts Observed: `FE, result @13, cmdEx @14`; map reply devType + guid; barcode
  reply devType, flag, index, len 0 (no proto); proto replies u32 len + proto.
- Start reply UnitChlStartInfo {1 unit 1, 2 chl 1, 3 test 142}; confirm reply ConfirmChl
  {1, 1, result 0}.

## Problems
None.

## Questions
- Q6 (b) answered by this run. Still open: (a) mask vs number for channels > 1;
  (c) whether the GUI shows anything different for test 142 (we skip the GUI's MySQL
  XML-info update).
