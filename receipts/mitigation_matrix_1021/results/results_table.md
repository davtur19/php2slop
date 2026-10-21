| lane | step | HTTP | resp bytes | sha256[:12] | OOM tried | fatal in body |
|---|---|---|---|---|---|---|
| A | effective_ini | 200 | 612 | `1ea3b05811a4` |  | no |
| A | baseline_consumer_stored | 200 | 322 | `f02f5c8e53ce` | 266240 | yes |
| A | producer_arm | 200 | 0 | `e3b0c44298fc` |  | no |
| A | consumer_after | 200 | 3 | `de34ad408f98` |  | no |
| A | consumer_after_2 | 200 | 3 | `de34ad408f98` |  | no |
| B | effective_ini | 200 | 618 | `72362434d29e` |  | no |
| B | baseline_consumer_stored | 200 | 3 | `de34ad408f98` |  | no |
| B | arm_1 | 200 | 3 | `de34ad408f98` |  | no |
| B | arm_2 | 200 | 3 | `de34ad408f98` |  | no |
| B | arm_3 | 200 | 3 | `de34ad408f98` |  | no |
| B | arm_4 | 200 | 3 | `de34ad408f98` |  | no |
| B | arm_5 | 200 | 3 | `de34ad408f98` |  | no |
| B | consumer_after_1 | 200 | 3 | `de34ad408f98` |  | no |
| B | consumer_after_2 | 200 | 3 | `de34ad408f98` |  | no |
| B | plant_state | 200 | 11 | `0768435b090c` |  | no |
| B | state_before_arm | 200 | 21 | `c37a5a1f9350` |  | no |
| B | arm_on_state | 200 | 3 | `de34ad408f98` |  | no |
| B | state_after_arm | 200 | 21 | `c37a5a1f9350` |  | no |
| B | oversize_beyond_post_max | 200 | 3 | `de34ad408f98` |  | no |
| C | effective_ini | 200 | 612 | `053704131ccd` |  | no |
| C | arm_1 | 200 | 0 | `e3b0c44298fc` |  | no |
| C | arm_2 | 200 | 0 | `e3b0c44298fc` |  | no |
| C | arm_3 | 200 | 0 | `e3b0c44298fc` |  | no |
| B2 | effective_ini | 200 | 618 | `f86b1f67dc32` |  | no |
| B2 | oversize_arm | 200 | 0 | `e3b0c44298fc` |  | no |
| B3 | effective_ini | 200 | 621 | `45a7c300b771` |  | no |
| B3 | oversize_arm | 200 | 3 | `de34ad408f98` |  | no |
| B4 | effective_ini | 200 | 618 | `2cd03f40111d` |  | no |
| B4 | arm_1 | 200 | 3 | `41208e228a3f` |  | no |
| B4 | arm_2 | 200 | 3 | `41208e228a3f` |  | no |
| B4 | consumer_after | 200 | 3 | `41208e228a3f` |  | no |
| B4 | oversize_beyond_post_max | 200 | 3 | `41208e228a3f` |  | no |
| D | effective_ini | 200 | 610 | `b9bffc2cefd4` |  | no |
| D | baseline_consumer_stored | 200 | 3 | `de34ad408f98` |  | no |
| D | arm_1 | 200 | 3 | `de34ad408f98` |  | no |
| D | arm_2 | 200 | 3 | `de34ad408f98` |  | no |
| D | arm_3 | 200 | 3 | `de34ad408f98` |  | no |
| D | consumer_after_1 | 200 | 3 | `de34ad408f98` |  | no |
| D | consumer_after_2 | 200 | 3 | `de34ad408f98` |  | no |
| D0 | effective_ini | 200 | 626 | `ff24097d7afa` |  | no |
| D0 | arm_unmitigated | 200 | 149 | `561043a1e978` | 266240 | yes |
| D0 | consumer_after | 200 | 3 | `de34ad408f98` |  | no |
