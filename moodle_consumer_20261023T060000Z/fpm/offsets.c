#include "php.h"
#include "ext/standard/basic_functions.h"
#include "ext/standard/php_var.h"
#include <stddef.h>
#include <stdio.h>
struct php_serialize_data_local { HashTable ht; uint32_t n; };
int main(void) {
    printf("sizeof_bg=%zu\n", sizeof(php_basic_globals));
    printf("off_serialize_lock=%zu\n", offsetof(php_basic_globals, serialize_lock));
    printf("off_serialize_data=%zu\n", offsetof(php_basic_globals, serialize) + offsetof(struct { struct php_serialize_data *data; unsigned level; }, data));
    printf("off_serialize_level=%zu\n", offsetof(php_basic_globals, serialize) + offsetof(struct { struct php_serialize_data *data; unsigned level; }, level));
    printf("off_unserialize_data=%zu\n", offsetof(php_basic_globals, unserialize) + offsetof(struct { struct php_unserialize_data *data; unsigned level; }, data));
    printf("off_unserialize_level=%zu\n", offsetof(php_basic_globals, unserialize) + offsetof(struct { struct php_unserialize_data *data; unsigned level; }, level));
    printf("off_serialize_ht_nNumUsed=%zu\n", offsetof(php_basic_globals, serialize) + offsetof(struct { struct php_serialize_data *data; unsigned level; }, data) + 0); /* placeholder */
    printf("sizeof_hash=%zu off_nNumUsed=%zu off_nTableSize=%zu off_arData=%zu\n", sizeof(HashTable), offsetof(HashTable, nNumUsed), offsetof(HashTable, nTableSize), offsetof(HashTable, arData));
    printf("sizeof_serdata=%zu off_ht=%zu off_n=%zu\n", sizeof(struct php_serialize_data_local), offsetof(struct php_serialize_data_local, ht), offsetof(struct php_serialize_data_local, n));
    return 0;
}
