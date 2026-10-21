# Measured lane results (nginx 1.30.1 edge -> PHP 8.5.10 FPM)

Arm shape: multipart body, `PHPSESSID` field + optional
`PHP_SESSION_UPLOAD_PROGRESS` field + N file parts with `F`*262144
filenames. Stock arm = 4,983,500 B. `PHP reached` = an FPM access-log
line exists for the request OR a PHP fatal was logged. (FPM does not
write an access line for a request that dies pre-RINIT, so the error
log is the authoritative signal for a fatal.)

| lane | scenario | body B | HTTP | PHP reached | PHP fatal | OOM limit/tried | evidence |
|---|---|---:|---:|---|---|---|---|
| N0 | N0_arm_stock_4983500 | 4983500 | 200 | yes | yes | 8388608/266240 | resp=196B |
| N0 | N0_arm_notoken_4983404 | 4983404 | 200 | yes | yes | 8388608/266240 | resp=351B |
| N0 | N0_fat_shortnames_4980659 | 4980659 | 200 | yes | no | - | resp=594B; script output |
| N0 | N0_variant_8parts_1836238 | 1836238 | 200 | yes | yes | 8388608/1314816 | resp=196B |
| N0 | N0_variant_8parts_280k | 1961230 | 200 | yes | yes | 8388608/1122304 | resp=196B |
| N1 | N1_arm_stock_4983500 | 4983500 | 413 | NO | no | - | resp=348B |
| N1 | N1_arm_stock_chunked | 4983500 | 413 | NO | no | - | resp=348B |
| N1 | N1_variant_8parts_1836238 | 1836238 | 200 | yes | no | - | resp=598B; script output; new sess sess_armsess1021 |
| N1 | N1_variant_8parts_280k | 1961230 | 200 | yes | no | - | resp=598B; script output; sess updated upload_progress |
| N1 | N1_legit_upload | 1435 | 200 | yes | no | - | resp=590B |
| N1 | N1_probe_ini | 0 | 200 | yes | no | - | - |
| N2 | N2_arm_stock_4983500 | 4983500 | 413 | NO | no | - | resp=348B |
| N2 | N2_variant_6parts | 1311696 | 200 | yes | yes | 8388608/1052672 | resp=730B; script output; new sess sess_armsess1021 |
| N2 | N2_variant_8parts_1836238 | 1836238 | 200 | yes | yes | 8388608/266240 | resp=196B; sess updated upload_progress |
| N2 | N2_variant_8parts_280k | 1961230 | 200 | yes | yes | 8388608/1122304 | resp=196B |
| N2 | N2_at_cap_2090030 | 2090030 | 200 | yes | yes | 8388608/1196032 | resp=196B |
| N4 | N4_legit_small | 1435 | 200 | yes | no | - | resp=590B |
| N4 | N4_arm_stock_4983500 | 4983500 | 413 | NO | no | - | resp=348B |
| N4 | N4_burst_01 | 1435 | 200 | yes | no | - | resp=590B |
| N4 | N4_burst_02 | 1435 | 200 | yes | no | - | resp=590B |
| N4 | N4_burst_03 | 1435 | 200 | yes | no | - | resp=590B |
| N4 | N4_burst_04 | 1435 | 200 | yes | no | - | resp=590B |
| N4 | N4_burst_05 | 1435 | 200 | yes | no | - | resp=590B |
| N4 | N4_burst_06 | 1435 | 429 | NO | no | - | resp=327B |
| N4 | N4_burst_07 | 1435 | 429 | NO | no | - | resp=327B |
| N4 | N4_burst_08 | 1435 | 429 | NO | no | - | resp=327B |
| N4 | N4_burst_09 | 1435 | 429 | NO | no | - | resp=327B |
| N4 | N4_burst_10 | 1435 | 429 | NO | no | - | resp=327B |
| N4 | N4_arm_after_burst | 4983500 | 413 | NO | no | - | resp=348B |
| SHAPE | shape_quoted_control | 338 | 200 | yes | no | - | resp=543B; script output; new sess sess_sessshapequoted001 |
| SHAPE | shape_unquoted | 336 | 200 | yes | no | - | resp=543B; script output; new sess sess_sessshapeunquoted1 |
| SHAPE | shape_lowercase | 338 | 200 | yes | no | - | resp=543B; script output; new sess sess_sessshapelower0001 |
| SHAPE | shape_percent_encoded | 392 | 200 | yes | no | - | resp=598B; script output; new sess sess_sessshapeperc00001 |
| SHAPE | shape_no_token | 242 | 200 | yes | no | - | resp=515B; script output; new sess sess_sessshapenone00001 |
| SHAPE | shape_single_quoted_name | 245 | 200 | yes | no | - | resp=533B; script output; new sess sess_sessshapesingle001 |
| SHAPE | shape_probe_tokrename_ini | 0 | 200 | yes | no | - | - |
| N3 | N3_arm_stock_4983500 | 4983500 | 403 | NO | no | - | resp=127B |
| N3 | N3_small_token_shape | 338 | 403 | NO | no | - | resp=127B |
| N3 | N3_legit_upload | 1435 | 200 | yes | no | - | resp=590B |
| N3 | N3_legit_upload_token_in_filename | 1463 | 403 | NO | no | - | resp=127B |
| N3 | N3_arm_notoken_4983404 | 4983404 | 200 | yes | yes | 8388608/266240 | resp=196B |
| N3 | N3_arm_userini_dir_default_field | 4983500 | 403 | NO | no | - | resp=127B |
| N3 | N3_arm_userini_UPGX_field | 4983477 | 200 | yes | yes | 8388608/266240 | resp=196B; new sess sess_armsess1021 |
| N3 | N3_arm_token_after_parts_4983500 | 4983500 | 403 | NO | no | - | resp=127B |
| N3-8k | N3_8k_arm_token_after_parts_4983500 | 4983500 | 200 | yes | yes | 8388608/266240 | resp=196B |
| N3-8k | N3_8k_arm_stock_4983500 | 4983500 | 403 | NO | no | - | resp=127B |
| N3 | N3_arm_percent_field | 4983502 | 200 | yes | yes | 8388608/266240 | resp=196B |
| N3-core | N3core_small_token_if_request_body | 337 | 200 | yes | no | - | resp=539B; script output; new sess sess_sesscoreapprox001 |

## Headroom measurements (fresh worker per request, token field present)

| parts | body B | max limit WITH fatal | min limit with 0 fatal | k = limit/body |
|---:|---:|---:|---:|---:|
| 4 | 787154 | 0 | 8388608 | 10.66 |
| 6 | 1311696 | 0 | 8388608 | 6.40 |
| 8 | 459982 | 3145728 | 4194304 | 9.12 |
| 8 | 918734 | 5242880 | 6291456 | 6.85 |
| 8 | 1836238 | 11534336 | 12582912 | 6.85 |
| 8 | 2090030 | 8388608 | 12582912 | 6.02 |
| 8 | 3671246 | 24117248 | 25165824 | 6.85 |
| 20 | 4983500 | 28311552 | 29360128 | 5.89 |
