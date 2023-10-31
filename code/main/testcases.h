#ifndef TESTCASES_H
#define TESTCASES_H

typedef void hash_f( const uint8_t *data, size_t len, uint8_t *hash );
typedef void rsa_f(  const uint8_t *data, uint8_t *output );

void test_signatures( hash_f *hf, rsa_f *rf );

#endif
