# No-upload mitigation battery - raw result rows
PHP fatal = `Fatal error` in the pool error log.  OOM = `Allowed memory size ... exhausted` line.  `FPM acc line` = a PHP-FPM access-log line was written for the request (pre-RINIT fatals produce none).

## U0

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U0 | U0_arm_stock_4983500 | 4983500 | 200 | 351 | YES | 8388608 / 266240 | 0 | sess_armsess1021 (yes) | YES | baseline reproduction of the OOM arm |
| U0 | U0_small_multipart_sanity | 1333 | 200 | 673 | no | - | 1 | sess_smallfiled001 (yes) | no | lane works end-to-end: parser + script output |
| U0 | U0_rawpost_phpinput | 7 | 200 | 258 | no | - | 1 | - (no) | no | php://input + $_POST availability |

## U1

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U1 | U1_arm_file_uploads_off | 4983500 | 200 | 630 | no | - | 1 | sess_armsess1021 (no) | no | file_uploads=0 vs byte-exact arm |
| U1 | U1_small_multipart_file_uploads_off | 1333 | 200 | 632 | no | - | 1 | sess_smallfiled001 (no) | no | $_FILES / warning behaviour with file_uploads=0 |
| U1 | U1b_arm_file_uploads_off_rerun | 4983500 | 200 | 630 | no | - | 1 | sess_armsess1021 (no) | no | clean re-run after forcing a fresh compile of index.php |
| U1 | U1_arm_peak_memory | 4983500 | 200 | 419 | no | - | 1 | sess_armsess1021 (no) | no | request-time peak with file_uploads=0 during the 4.98MB arm |
| U1 | U1_small_peak_memory | 332 | 200 | 418 | no | - | 1 | sess_peaksmall001 (no) | no | baseline peak for a tiny multipart request |
| U1 | U1_legit_upload_blocked | 1435 | 200 | 300 | no | - | 1 | - (no) | no | tradeoff: legitimate upload with file_uploads=0 |
| U1 | U1c_arm_clean_freshtarget | 4983500 | 200 | 630 | no | - | 1 | sess_armsess1021 (no) | no | arm against a freshly compiled target: INI report + behaviour |

## U1cgi

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U1cgi | U1cgi_arm_file_uploads_off | 4983500 | 200 | 633 | no | - | 0 | sess_armsess1021 (no) | no | file_uploads=0 via php-cgi (cross-SAPI confirmation) |
| U1cgi | U1cgi_small_multipart_file_uploads_off | 333 | 200 | 635 | no | - | 0 | sess_cgismall00001 (no) | no | php-cgi file_uploads=0: normal fields parsed, file parts dropped, no warning |
| U1cgi | U1cgi_legit_upload_blocked | 1435 | 200 | 300 | no | - | 0 | - (no) | no | php-cgi file_uploads=0: legitimate upload silently dropped |

## U2

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U2 | U2_arm_enable_post_data_reading_off | 4983500 | 200 | 593 | no | - | 1 | sess_armsess1021 (no) | no | enable_post_data_reading=0 vs byte-exact arm |
| U2 | U2_urlencoded_post | 7 | 200 | 313 | no | - | 1 | - (no) | no | tradeoff: normal POST endpoint with POST parsing disabled |
| U2 | U2_small_multipart | 1333 | 200 | 595 | no | - | 1 | sess_smallfiled001 (no) | no | multipart body under no-parse regime |
| U2 | U2_rawpost_phpinput | 7 | 200 | 255 | no | - | 1 | - (no) | no | php://input + $_POST availability |
| U2 | U2_legit_upload_blocked | 1435 | 200 | 300 | no | - | 1 | - (no) | no | tradeoff: legitimate upload with enable_post_data_reading=0 |

## U3

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U3 | U3_arm_multipart_415 | 4983500 | 415 | 342 | no | - | 0 | - (no) | no | coarse edge rule must answer 415 before PHP |
| U3 | U3_urlencoded_post_ok | 7 | 200 | 312 | no | - | 1 | - (no) | no | legit urlencoded POST must still work |
| U3 | U3_get_no_body | 0 | 415 | 342 | no | - | 0 | - (no) | no | legit GET unaffected |
| U3 | U3_get_with_multipart_ct_header | 0 | 415 | 342 | no | - | 0 | - (no) | no | GET carrying a multipart CT header (no body) |
| U3 | U3_legit_multipart_upload | 1435 | 415 | 342 | no | - | 0 | - (no) | no | tradeoff: real upload endpoint rejected by the rule |
| U3 | U3_get_no_body_plain | 0 | 200 | 1123 | no | - | 1 | - (no) | no | legit GET, no Content-Type header |
| U3 | U3_small_multipart_MixedCase_CT | 334 | 415 | 342 | no | - | 0 | - (no) | no | case-insensitive map regex check |

## U3b

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U3b | U3b_arm_multipart_415 | 4983500 | 415 | 342 | no | - | 0 | - (no) | no | refined rule (POST/PUT/PATCH only) vs arm |
| U3b | U3b_urlencoded_post_ok | 7 | 200 | 312 | no | - | 1 | - (no) | no | legit urlencoded POST |
| U3b | U3b_get_with_multipart_ct_header | 0 | 200 | 1124 | no | - | 1 | - (no) | no | GET with multipart CT header must be unaffected by refined rule |
| U3b | U3b_legit_multipart_upload | 1435 | 415 | 342 | no | - | 0 | - (no) | no | tradeoff: upload endpoints still blocked |
| U3b | U3b_get_no_body_plain | 0 | 200 | 1124 | no | - | 1 | - (no) | no | legit GET, no Content-Type header (refined rule) |
| U3b | U3b_post_urlencoded_with_boundaryish_ct | 3 | 200 | 308 | no | - | 1 | - (no) | no | urlencoded POST with charset param still 200 |
| U3b | U3b_small_multipart_MixedCase_CT | 334 | 415 | 342 | no | - | 0 | - (no) | no | refined rule case-insensitive check |

## U4

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U4 | U4_arm_413_128k | 4983500 | 413 | 348 | no | - | 0 | - (no) | no | 128k cap alone vs 4.98MB arm |
| U4 | U4_small_multipart_with_progress_1332 | 1332 | 200 | 672 | no | - | 1 | sess_smallu4sid01 (yes) | no | tiny multipart still reaches the parser? (fatal at 8M?) |
| U4 | U4_dense_small_118713 | 118713 | 200 | 801 | no | - | 1 | sess_densesid001 (yes) | no | filename-dense body just under 128k at 8M |
| U4 | U4_body_130000_413 | 130000 | 200 | 678 | no | - | 1 | sess_dbd1e0365e011b01bda4639dd13821a8 (no) | no | cap boundary: 130000 B > 128k |
| U4 | U4_legit_upload_1435 | 1435 | 200 | 557 | no | - | 1 | - (no) | no | legit small upload under the cap still works |
| U4 | U4_body_131072_at_cap | 131072 | 200 | 677 | no | - | 1 | sess_053acf86b1d1c610cd3f8e663444f773 (no) | no | exactly at client_max_body_size 128k |
| U4 | U4_body_140000_over_cap | 140000 | 413 | 348 | no | - | 0 | - (no) | no | over the 128k cap -> expect 413 |

## U5

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U5 | U5_arm_max_file_uploads_0 | 4983500 | 200 | 1019 | no | - | 1 | - (no) | no | max_file_uploads=0 vs byte-exact arm |
| U5 | U5_two_files_warning | 2458 | 200 | 1019 | no | - | 1 | - (no) | no | warning text / $_FILES count with max_file_uploads=0 |
| U5 | U5_fields_only_no_filepart | 178 | 200 | 604 | no | - | 1 | sess_nofilepart01 (no) | no | max_file_uploads=0: no file part -> warning should not appear |
| U5 | U5_legit_upload_blocked | 1435 | 200 | 618 | no | - | 1 | - (no) | no | tradeoff: legitimate upload with max_file_uploads=0 |

## U6

| lane | case | body B | HTTP | resp B | PHP fatal | OOM limit/tried | FPM acc line | new session (upload_progress) | worker changed | note |
|---|---|---:|---:|---:|---|---|---|---|---|---|
| U6 | U6_arm_post_max_size_0 | 4983500 | 200 | 351 | YES | 8388608 / 266240 | 0 | sess_armsess1021 (yes) | YES | post_max_size=0 semantics: does it disable POST or mean unlimited? |
| U6 | U6_urlencoded_post | 7 | 200 | 311 | no | - | 1 | - (no) | no | post_max_size=0 vs a normal urlencoded POST |
