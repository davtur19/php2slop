#include "php.h"
#include "ext/standard/basic_functions.h"
#include "ext/standard/php_var.h"
#include <stddef.h>
#include <stdio.h>
struct php_serialize_data_local { HashTable ht; uint32_t n; };
int main(void) {
    printf("sizeof_bg=%zu lock=%zu data=%zu level=%zu unser_data=%zu unser_level=%zu\n",
      sizeof(php_basic_globals),
      offsetof(php_basic_globals, serialize_lock),
      offsetof(php_basic_globals, serialize) + offsetof(struct { struct php_serialize_data *data; unsigned level; }, data),
      offsetof(php_basic_globals, serialize) + offsetof(struct { struct php_serialize_data *data; unsigned level; }, level),
      offsetof(php_basic_globals, unserialize) + offsetof(struct { struct php_unserialize_data *data; unsigned level; }, data),
      offsetof(php_basic_globals, unserialize) + offsetof(struct { struct php_unserialize_data *data; unsigned level; }, level));
    printf("sizeof_hash=%zu nNumUsed=%zu nTableSize=%zu arData=%zu sizeof_serdata=%zu off_n=%zu\n",
      sizeof(HashTable), offsetof(HashTable,nNumUsed), offsetof(HashTable,nTableSize), offsetof(HashTable,arData),
      sizeof(struct php_serialize_data_local), offsetof(struct php_serialize_data_local,n));
    return 0;
}
