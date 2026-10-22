# PHPGGC chain inventory (standalone extract)

Source: `/tmp/opencode/research/phpsessinj_1792633613`
Date: 2026-10-22
Purpose: the 170-chain `phpggc -l` inventory is cited by more than one receipt; this directory keeps the extract and its checkout provenance without the surrounding session-injection lab.

## Contents

| file | content |
|---|---|
| `phpggc_full.txt` | full `phpggc -l` output, 170 chains, header `Gadget Chains` plus per-chain name/version/type/vector |
| `phpggc_checkout.txt` | checkout path, commit, date, describe, and the headers of the chains used in the MediaWiki/OpenMage work |

## Provenance and counts

* PHPGGC commit **`f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c`** (2025-09-29, describe `f8aebde`).
* **170 chains total.** Notable counts: Laravel 23, Symfony 19, WordPress 18 (including two WooCommerce plugin chains), Drupal 11, Joomla 1, Magento 4; the remainder are CodeIgniter, Doctrine, Guzzle, Monolog, Yii, Zend Framework and other libraries.
* **Native / PHP-internal chains: 0.** Nothing in the inventory targets a class shipped by PHP core, which is why the pre-RINIT decode path (internal + preloaded classes only) has no native POP chain.

## How to read it

The inventory is a *library coverage* list, not a reachability result. A chain is only usable when the matching library version is installed **and** the class is autoloadable at the moment the vulnerable `unserialize()` runs. `phpggc_checkout.txt` records the specific chain headers (`Guzzle/FW/1`, `MediaWiki/FD/1`, `Monolog/RCE/8`, `Monolog/RCE/9`, `Monolog/FW/1`, `Monolog/RCE/2`) that were checked against the lab versions; reachability findings live in `phpsessinj_1022/`, `apppop_1022/` and `openmage_pop_1022/`.

The `phpggc` working tree and generated payloads are not included; the inventory is reproducible from the pinned commit.
