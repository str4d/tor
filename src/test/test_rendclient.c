/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define RENDCLIENT_PRIVATE

#include "rendclient.h"

#include "or.h"
#include "rendcache.h"

/* Test suite stuff */
#include "test.h"

#define STR_HS_DIR_ID_DIGEST "cccccccccccccccccccc"
#define STR_HS_ADDR "ajhb7kljbiru65qo"
#define STR_HS_COOKIE "aaaaaaaaaaaaaaaaaaaaaa"

static void
test_rend_client_purge_hidden_service(void *arg)
{
  time_t now = time(NULL);
  routerstatus_t hs_dir;
  char desc_id[DIGEST_LEN];
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  (void) arg;

  rend_cache_init();

  memset(&hs_dir, 0, sizeof(hs_dir));
  strncpy(hs_dir.identity_digest, STR_HS_DIR_ID_DIGEST, DIGEST_LEN);

  rend_compute_v2_desc_id(desc_id, STR_HS_ADDR, NULL, now, 0);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_id, DIGEST_LEN);

  /* cache serv request time */
  lookup_last_hid_serv_request(&hs_dir, desc_id_base32, now, 1);
  tt_int_op(now, OP_EQ, lookup_last_hid_serv_request(&hs_dir, desc_id_base32,
                                                     0, 0));

  /* purge hidden service */
  rend_client_purge_hidden_service(STR_HS_ADDR, NULL);
  tt_int_op(0, OP_EQ, lookup_last_hid_serv_request(&hs_dir, desc_id_base32,
                                                   0, 0));

 done:
  rend_cache_free_all();
}

static void
test_rend_client_purge_hidden_service_with_cookie(void *arg)
{
  time_t now = time(NULL);
  routerstatus_t hs_dir;
  char desc_id[DIGEST_LEN];
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  (void) arg;

  rend_cache_init();

  memset(&hs_dir, 0, sizeof(hs_dir));
  strncpy(hs_dir.identity_digest, STR_HS_DIR_ID_DIGEST, DIGEST_LEN);

  int replica = 1;
  tt_int_op(replica, OP_LT, REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS);
  rend_compute_v2_desc_id(desc_id, STR_HS_ADDR, STR_HS_COOKIE, now, replica);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_id, DIGEST_LEN);

  /* cache serv request time */
  lookup_last_hid_serv_request(&hs_dir, desc_id_base32, now, 1);
  tt_int_op(now, OP_EQ, lookup_last_hid_serv_request(&hs_dir, desc_id_base32,
                                                     0, 0));

  /* purge hidden service */
  rend_client_purge_hidden_service(STR_HS_ADDR, STR_HS_COOKIE);
  tt_int_op(0, OP_EQ, lookup_last_hid_serv_request(&hs_dir, desc_id_base32,
                                                   0, 0));

 done:
  rend_cache_free_all();
}

struct testcase_t rend_client_tests[] = {
  { "purge_hidden_service", test_rend_client_purge_hidden_service, 0, NULL,
    NULL },
  { "purge_hidden_service_with_cookie",
    test_rend_client_purge_hidden_service_with_cookie, 0, NULL, NULL },
  END_OF_TESTCASES
};

