/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <string.h>
#include <getopt.h>

#ifdef __ANDROID__
#include <jni.h>
#include <android/log.h>
#endif

#include "dap_common.h"
#include "dap_config.h"
#include "dap_cert.h"
#include "dap_cert_file.h"
#include "dap_chain_wallet.h"
#include "dap_file_utils.h"
#include "json.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_tx.h"

#define LOG_TAG "CellframeNative"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static struct option const options[] =
{
  {"wallet", required_argument, 0, 'w'},
  {"password", required_argument, 0, 'p'},
  {"filename", required_argument, 0, 'f'},
  {"out", required_argument, 0, 'o'},
  {"create", no_argument, 0, 'c'},
  {"sign-type", required_argument, 0, 's'},
  {"path", required_argument, 0, 'd'},
  {"help", no_argument, 0, 'h'},
  {"seed", required_argument, 0, 'z'},
  {"beauty", required_argument, 0, 'b'},
  {"get-addr", no_argument, 0, 'a'},
  {"net-id", required_argument, 0, 'i'},
  {"version", no_argument, 0, 'v'},
};

static dap_chain_datum_tx_t* json_parse_input_tx (json_object* a_in);
static char* convert_tx_to_json_string(dap_chain_datum_tx_t *a_tx, bool a_beauty);
static int s_wallet_create(const char *a_wallet_path, const char *a_wallet_name, const char *a_pass, const char *a_sig_type, const char *a_seed);

void bad_option(){
    printf("Usage: %s {{-w, --wallet <path_to_wallet_file> | -z, --seed <seed_phrase> -s <sign_type>} [OPTIONS] | {-c -w <wallet_name> -d <path_to_save_wallet_file> -s <sign_type> -z <seed_phrase>} | {-a {-w <path_to_wallet_file> | -z, --seed <seed_phrase> -s <sign_type>} -i 0x<net_id>}} \n\r"
            "Signs the datum passed to the input by specified wallet and send its items in json-format.\n\r"
            "Datum sign options:\n\r"
            "\t-w, --wallet     specifies path to wallet for datum sign or wallet name\n\r"
            "\t-p, --password     specifies walled password if needed\n\r"
            "\t-f, --filename   specifies input json-file wits datum items. If not specified, it will be received from stdin\n\r"
            "\t-o, --out        specifies output json-file. If not specified, it will be send into stdout\n\r"
            "\t-b, --beauty     enables output JSON beautification\n\r"
            "\n\r"
            "\t-c, --create     create wallet -w with password -p\n\r"
            "Wallet create options:\n\r"
            "\t-w, --wallet     specifies wallet name\n\r"
            "\t-d, --path       specifies path to save wallet file\n\r"
            "\t-s, --sign-type  specifies wallet sign type. Available options: sig_dil, sig_falcon\n\r"
            "\t-z, --seed       specifies seed phrase\n\r"
            "Wallet get address:\n\r"
            "\t-a, --get-addr   print wallet address in specified net\n\r"
            "\t-w, --wallet     specifies path to wallet file\n\r"
            "\t-z, --seed       specifies seed phrase\n\r"
            "\t-i, --net-id     hex id of net\n\r"
            "Exapmple of usage for datum sign:\n\r\n\r"
            "\tUsing .dwallet file: cellframe-tool-sign --wallet /home/user1/wallets/mywal.dwallet -f ~/in.json -o ~/out.json\n\r\n\r"
            "\tUsing seed phrase: cellframe-tool-sign -seed \"my seed phrase\" -s sig_dil -f ~/in.json -o ~/out.json\n\r\n\r"
            "Exapmple of usage for wallet creating:\n\r\n\r"
            "\tcellframe-tool-sign --create -d /home/user1/wallets -w mywal -s sig_dil -z \"word1 word2 word3\"\n\r\n\r"
            "Exapmple of usage for printing wallet address:\n\r\n\r"
            "\tBackbone net:\n\r"
            "\tUsing .dwallet file: cellframe-tool-sign --get-addr -w /home/user1/wallets/mywal.dcert -i 0x0404202200000000\n\r\n\r"
            "\tUsing seed phrase: cellframe-tool-sign --get-addr -seed \"my seed phrase\" -s sig_dil -i 0x0404202200000000\n\r\n\r"
            "\tKelVPN net:\n\r"
            "\tUsing .dwallet file: cellframe-tool-sign --get-addr -w /home/user1/wallets/mywal.dcert -i 0x1807202300000000\n\r\n\r"
            "\tUsing seed phrase: cellframe-tool-sign --get-addr -seed \"my seed phrase\" -s sig_dil -i 0x1807202300000000\n\r\n\r",

            dap_get_appname());

    exit(EXIT_FAILURE);
}

void print_version()
{
    printf("cellframe-tool-sign "DAP_VERSION" "BUILD_HASH" "BUILD_TS"\n");
}

int main(int argc, char **argv)
{
    dap_set_appname("cellframe-tool-sign");
   
    if (argc == 1){
        bad_option();
    }

    char *l_input_data = NULL;

    // get relative path to config
    const char *l_wallet_str = NULL;
    const char *l_wallet_path = NULL;
    const char *l_wallet_name = NULL;
    const char *l_in_file_path = NULL;
    const char *l_out_file_path = NULL;
    const char *l_pwd = NULL;
    const char *l_seed_str = NULL;
    const char *l_sign_type = NULL;
    const char *l_net_id_str = NULL;
    bool l_beautification = false;
    bool l_create_wallet = false;
    bool l_get_wallet_addr = false;

    int optc = 0;
    int option_index = 0;
    while ((optc = getopt_long(argc, argv, "w:p:f:o:bcs:d:hz:ai:v", options, &option_index)) != -1){
        switch(optc){
        case 'w':{
            l_wallet_str = dap_strdup(optarg);
        }break;
        case 'p':{
            l_pwd = dap_strdup(optarg);       
        }break;
        case 'f':{
            l_in_file_path = dap_strdup(optarg);
        }break;
        case 'o':{
            l_out_file_path = dap_strdup(optarg);
        }break;
        case 'b':{
            l_beautification = true;
        }break;
        case 'c':{
            l_create_wallet = true;
        }break;
        case 'd':{
            l_wallet_path = dap_strdup(optarg);
        }break;
        case 's':{
            l_sign_type = dap_strdup(optarg);
        }break;
        case 'z':{
            l_seed_str = dap_strdup(optarg);
        }break;
        case 'a':{
            l_get_wallet_addr = true;
        }break;
        case 'i':{
            l_net_id_str = dap_strdup(optarg);
        }break;
        case 'v':{
            print_version();
            return 0;
        }break;
        default:
            bad_option();
        }
    }

    if (l_create_wallet){
        l_wallet_name = l_wallet_str;
    } else {
        l_wallet_path = l_wallet_str;
    }
    
    if (!l_wallet_path && !l_seed_str){
        printf("Path to wallet or seed phrase must be specified!\n\r");
        return -1;
    }

    if (l_get_wallet_addr && !l_net_id_str){
        printf("Net id must be specified for getting wallet addr!\n\r");
        return -1;
    }

    if (l_create_wallet){
        int l_res = s_wallet_create(l_wallet_path, l_wallet_name, l_pwd, l_sign_type, l_seed_str);
        if (l_res)
            printf("Error %d (%s)\n\r", errno, strerror(errno));
        return l_res;
    } else {
        l_wallet_path = l_wallet_str;
    }

    if (l_get_wallet_addr){
        if (l_wallet_path){
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_wallet_path, l_pwd, NULL);
            if(!l_wallet) {
                printf("Can't open wallet %s. Error %d (%s)\n\r", l_wallet_path, errno, strerror(errno));
                return errno;
            }
            uint64_t l_net_id_ui64 = strtoull(l_net_id_str, NULL, 16);
            dap_chain_net_id_t l_net_id = {.uint64 = l_net_id_ui64};
            dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(l_wallet, l_net_id);
            const char*l_addr_str = dap_chain_addr_to_str_static(l_addr);
            printf("Wallet addr for net with id %"DAP_UINT64_FORMAT_X":\n\r%s\n\r", l_net_id_ui64, l_addr_str);
            return 0;
        } else if (l_seed_str && l_sign_type) {
            const char* l_seed_hash_str = dap_get_data_hash_str(l_seed_str, strlen(l_seed_str)).s;
            size_t l_restore_str_size = dap_strlen(l_seed_hash_str);
            uint8_t *l_seed = NULL;
            size_t l_seed_size = 0;
            if (l_restore_str_size > 3 && !dap_strncmp(l_seed_hash_str, "0x", 2) && (!dap_is_hex_string(l_seed_hash_str + 2, l_restore_str_size - 2))) {
                l_seed_size = (l_restore_str_size - 2) / 2;
                l_seed = DAP_NEW_Z_SIZE(uint8_t, l_seed_size + 1);
                if(!l_seed) {
                    printf("Memory allocation error.\n\r");
                    exit(-100);
                }
                dap_hex2bin(l_seed, l_seed_hash_str + 2, l_restore_str_size - 2);
            } else {
                printf("Restored hash is invalid or too short, wallet is not created. Please use -seed 0x<hex_value>\n\r");
                exit(-1);
            }

            uint64_t l_net_id_ui64 = strtoull(l_net_id_str, NULL, 16);
            dap_chain_net_id_t l_net_id = {.uint64 = l_net_id_ui64};
            dap_enc_key_t *l_enc_key = dap_enc_key_new_generate(dap_sign_type_to_key_type(dap_sign_type_from_str(l_sign_type)), NULL, 0, l_seed, l_seed_size, 0);
            dap_chain_addr_t l_addr = {};
            dap_chain_addr_fill_from_key(&l_addr, l_enc_key, l_net_id);
            const char* l_addr_str = dap_chain_addr_to_str_static(&l_addr);
            printf("Wallet addr for net with id %"DAP_UINT64_FORMAT_X":\n\r%s\n\r", l_net_id_ui64, l_addr_str);
            dap_enc_key_delete(l_enc_key);
            return 0;
        } else {
            printf("-get-addr command requires --wallet or -seed, -sign_type parameters.\n\r");
            return -2;
        }       
    }

    FILE *l_input_file = NULL;
    if (!l_in_file_path){
        l_input_file = stdin;
    } else {
        l_input_file = fopen(l_in_file_path, "r");
        if (!l_input_file){
            printf("Can't open %s\n\r", l_in_file_path);
            return -1;
        }
    }

    char buffer[BUFSIZ] = {0};
    size_t l_bytes_read = 0;
    size_t l_total_bytes = 0;
    while((l_bytes_read = fread(buffer, sizeof(char), BUFSIZ, l_input_file)) > 0){
        l_input_data = DAP_REALLOC_COUNT(l_input_data, l_total_bytes + l_bytes_read);
        memcpy(l_input_data + l_total_bytes, buffer, l_bytes_read);
        l_total_bytes += l_bytes_read;
    }

    if (!l_input_data && !l_total_bytes){
        printf("Can't read input data. Error: ");
        perror(l_in_file_path);
        printf("\n\r");
        if (l_in_file_path)
            fclose(l_input_file);
        return -1;
    }

    if (l_in_file_path){
        fclose(l_input_file);
    }

    // Parse json
    struct json_object *l_json = json_tokener_parse(l_input_data);
    if (!l_json){
        printf("Can't parse json\n\r");
        DAP_DELETE(l_input_data);
        return -1;
    }

    // Make binary transaction
    dap_chain_datum_tx_t *l_tx = json_parse_input_tx (l_json);
    if (!l_tx){
        printf("Can't create tx\n\r");
        DAP_DELETE(l_input_data);
        return -1;
    }

    // Sign it
    // add 'sign' items
    dap_enc_key_t *l_owner_key = NULL;
    if (l_seed_str && l_sign_type) {
            const char* l_seed_hash_str = dap_get_data_hash_str(l_seed_str, strlen(l_seed_str)).s;
            size_t l_restore_str_size = dap_strlen(l_seed_hash_str);
            uint8_t *l_seed = NULL;
            size_t l_seed_size = 0;
            if (l_restore_str_size > 3 && !dap_strncmp(l_seed_hash_str, "0x", 2) && (!dap_is_hex_string(l_seed_hash_str + 2, l_restore_str_size - 2))) {
                l_seed_size = (l_restore_str_size - 2) / 2;
                l_seed = DAP_NEW_Z_SIZE(uint8_t, l_seed_size + 1);
                if(!l_seed) {
                    printf("Memory allocation error.\n\r");
                    dap_chain_datum_tx_delete(l_tx);
                    DAP_DELETE(l_input_data);
                    exit(-100);
                }
                dap_hex2bin(l_seed, l_seed_hash_str + 2, l_restore_str_size - 2);
            } else {
                printf("Restored hash is invalid or too short, wallet is not created. Please use -seed 0x<hex_value>\n\r");
                dap_chain_datum_tx_delete(l_tx);
                DAP_DELETE(l_input_data);
                exit(-1);
            }
            l_owner_key = dap_enc_key_new_generate(dap_sign_type_to_key_type(dap_sign_type_from_str(l_sign_type)), NULL, 0, l_seed, l_seed_size, 0);
    } else if (l_wallet_path){
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(l_wallet_path, l_pwd, NULL);
        if(!l_wallet) {
            dap_chain_datum_tx_delete(l_tx);
            printf("Can't open wallet %s\n\r", l_wallet_path);
            DAP_DELETE(l_input_data);
            return -1;
        }
        l_owner_key = dap_chain_wallet_get_key(l_wallet, 0);
    } else {
        dap_chain_datum_tx_delete(l_tx);
        printf("Wallet or seed_phrase+sig_type+net_id required for tx signing\n\r");
        DAP_DELETE(l_input_data);
        return -1;
    }

    if(!l_owner_key || dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_owner_key);
        printf("Can't add sign output\n\r");
        DAP_DELETE(l_input_data);
        return -1;
    }
    dap_enc_key_delete(l_owner_key);

    // Convert to JSON transaction
    char *l_out = convert_tx_to_json_string(l_tx, l_beautification);
    if (!l_out){
        dap_chain_datum_tx_delete(l_tx);
        printf("error\n\r");
        DAP_DELETE(l_input_data);
        return -1;
    }
    dap_chain_datum_tx_delete(l_tx);

    FILE *l_output_file = NULL;
    if (!l_out_file_path){
        l_output_file = stdout;
    } else {
        l_output_file = fopen(l_out_file_path, "w");
        if (!l_output_file){
            printf("Can't open %s\n\r", l_out_file_path);
            DAP_DELETE(l_out);
            DAP_DELETE(l_input_data);
            return -1;
        }
    }

    size_t out_bytes = fwrite(l_out, 1, strlen(l_out), l_output_file);
    if (l_out_file_path){
        fclose(l_output_file);
    }
    if (out_bytes <= 0){
        printf("Can't write result\n\r");
        DAP_DELETE(l_out);
        DAP_DELETE(l_input_data);
        return -1;
    }

    DAP_DELETE(l_out);
    DAP_DELETE(l_input_data);
    return 0;
}

static const char* s_json_get_text(struct json_object *a_json, const char *a_key)
{
    if(!a_json || !a_key)
        return NULL;
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json && json_object_is_type(l_json, json_type_string)) {
        // Read text
        return json_object_get_string(l_json);
    }
    return NULL;
}

static bool s_json_get_int64(struct json_object *a_json, const char *a_key, int64_t *a_out)
{
    if(!a_json || !a_key || !a_out)
        return false;
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json) {
        if(json_object_is_type(l_json, json_type_int)) {
            // Read number
            *a_out = json_object_get_int64(l_json);
            return true;
        }
    }
    return false;
}

static bool s_json_get_unit(struct json_object *a_json, const char *a_key, dap_chain_net_srv_price_unit_uid_t *a_out)
{
    const char *l_unit_str = s_json_get_text(a_json, a_key);
    if(!l_unit_str || !a_out)
        return false;
    dap_chain_net_srv_price_unit_uid_t l_unit = dap_chain_net_srv_price_unit_uid_from_str(l_unit_str);
    if(l_unit.enm == SERV_UNIT_UNDEFINED)
        return false;
    a_out->enm = l_unit.enm;
    return true;
}

static bool s_json_get_uint256(struct json_object *a_json, const char *a_key, uint256_t *a_out)
{
    const char *l_uint256_str = s_json_get_text(a_json, a_key);
    if(!a_out || !l_uint256_str)
        return false;
    uint256_t l_value = dap_chain_balance_scan(l_uint256_str);
    if(!IS_ZERO_256(l_value)) {
        memcpy(a_out, &l_value, sizeof(uint256_t));
        return true;
    }
    return false;
}

// service names: srv_stake, srv_vpn, srv_xchange
static bool s_json_get_srv_uid(struct json_object *a_json, const char *a_key_service_id, const char *a_key_service, uint64_t *a_out)
{
    uint64_t l_srv_id;
    if(!a_out)
        return false;
    // Read service id
    if(s_json_get_int64(a_json, a_key_service_id, (int64_t*) &l_srv_id)) {
        *a_out = l_srv_id;
        return true;
    }
    else {
        // Read service as name
        const char *l_service = s_json_get_text(a_json, a_key_service);
        if(l_service) {
            dap_chain_net_srv_t *l_srv = dap_chain_net_srv_get_by_name(l_service);
            if(!l_srv)
                return false;
            *a_out = l_srv->uid.uint64;
            return true;
        }
    }
    return false;
}

static dap_chain_wallet_t* s_json_get_wallet(struct json_object *a_json, const char *a_key)
{
    return dap_chain_wallet_open(s_json_get_text(a_json, a_key), dap_chain_wallet_get_path(g_config), NULL);
}

static const dap_cert_t* s_json_get_cert(struct json_object *a_json, const char *a_key)
{
    return dap_cert_find_by_name(s_json_get_text(a_json, a_key));
}

// Read pkey from wallet or cert
static dap_pkey_t* s_json_get_pkey(struct json_object *a_json)
{
    dap_pkey_t *l_pub_key = NULL;
    // From wallet
    dap_chain_wallet_t *l_wallet = s_json_get_wallet(a_json, "wallet");
    if(l_wallet) {
        l_pub_key = dap_chain_wallet_get_pkey(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
        if(l_pub_key) {
            return l_pub_key;
        }
    }
    // From cert
    const dap_cert_t *l_cert = s_json_get_cert(a_json, "cert");
    if(l_cert) {
        l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
    }
    return l_pub_key;
}

static dap_chain_datum_tx_t* json_parse_input_tx (json_object* a_json_in)
{
    if (!a_json_in){
        return NULL;
    }
    dap_chain_datum_tx_t *l_tx = NULL;
    if (dap_chain_net_tx_create_by_json(a_json_in, NULL, NULL, &l_tx, NULL, NULL) == 0){
        return l_tx;
    } else {
        printf("Can't create tx\n\r");
        return NULL;
    }
}


static char* convert_tx_to_json_string(dap_chain_datum_tx_t *a_tx, bool a_beauty)
{
    json_object *l_out_json = json_object_new_object();
    char *l_out = NULL;

    if (!dap_chain_net_tx_to_json(a_tx, l_out_json)){
        const char *l_out_buf = json_object_to_json_string_ext(l_out_json, a_beauty ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN);
        l_out = dap_strdup(l_out_buf);
        json_object_put(l_out_json);
    }

    return l_out;
}



static int s_wallet_create(const char *a_wallet_path, const char *a_wallet_name, const char *a_pass, const char *a_sig_type, const char *a_seed){
    dap_sign_type_t l_sig_type = dap_sign_type_from_str(a_sig_type);
    dap_chain_wallet_t *l_wallet = NULL;

    if ( l_sig_type.type == SIG_TYPE_NULL ) {
      printf("Invalid signature type '%s', you can use the following:\n\r%s",
              a_sig_type, dap_sign_get_str_recommended_types());
      exit( -2004 );
    }

    if (dap_sign_type_is_depricated(l_sig_type))
    {
        printf("Tesla, picnic, bliss algorithms is not supported, please, use another variant:\n\r%s",
                dap_sign_get_str_recommended_types());
        exit( -2004 );
    }

    uint8_t *l_seed = NULL;
    size_t l_seed_size = 0;

    if(a_seed) {
        const char* l_seed_hash_str = dap_get_data_hash_str(a_seed, strlen(a_seed)).s;
        size_t l_restore_str_size = dap_strlen(l_seed_hash_str);
        if (l_restore_str_size > 3 && !dap_strncmp(l_seed_hash_str, "0x", 2) && (!dap_is_hex_string(l_seed_hash_str + 2, l_restore_str_size - 2))) {
            l_seed_size = (l_restore_str_size - 2) / 2;
            l_seed = DAP_NEW_Z_SIZE(uint8_t, l_seed_size + 1);
            if(!l_seed) {
                printf("Memory allocation error.\n\r");
                exit(-100);
            }
            dap_hex2bin(l_seed, l_seed_hash_str + 2, l_restore_str_size - 2);
        } else {
            printf("Restored hash is invalid or too short, wallet is not created. Please use -seed 0x<hex_value>\n\r");
            exit(-1);
        }
    }

    if (l_sig_type.type == SIG_TYPE_MULTI_CHAINED){
        // if (argc < 7) {
        //     log_it(L_ERROR, "For a signature with type sig_multi_chained, two more signature type parameters must be set.");
        //     exit(-2006);
        // }
        // dap_sign_type_t l_types[MAX_ENC_KEYS_IN_MULTYSIGN] = {0};
        // size_t l_count_signs  = 0;
        // for (int i = 6; i < argc; i++) {
        //     l_types[l_count_signs] = dap_sign_type_from_str(argv[i]);
        //     if (l_types[l_count_signs].type == SIG_TYPE_NULL) {
        //         log_it( L_ERROR, "Invalid signature type '%s', you can use the following:\n%s",
        //                 argv[i], dap_sign_get_str_recommended_types());
        //         exit(-2007);
        //     }
        //     if (dap_sign_type_is_depricated(l_types[l_count_signs]))
        //     {
        //         log_it( L_ERROR, "Tesla, picnic, bliss algorithms is not supported, please, use another variant:\n%s",
        //                 dap_sign_get_str_recommended_types());
        //         exit( -2008 );
        //     }
        //     l_count_signs++;
        // }
        // l_wallet = dap_chain_wallet_create_with_seed_multi(l_wallet_name, s_system_wallet_dir,
        //                                                        l_types, l_count_signs,
        //                                                        NULL, 0, NULL);
        printf("Multisigned wallet not supported yet.\n\r");
        return -1;
    } else {
        if (!l_seed)
            l_wallet = dap_chain_wallet_create(a_wallet_name, a_wallet_path, l_sig_type, a_pass);
        else 
            l_wallet = dap_chain_wallet_create_with_seed(a_wallet_name, a_wallet_path, l_sig_type, l_seed, l_seed_size, a_pass);
    }
        

    if (l_wallet) {
        printf("Wallet %s has been created.\n\r", a_wallet_name);
        return 0;
    } else {
        printf("Failed to create a wallet.\n\r");
        return -1;
    }
}

#ifdef __ANDROID__
JNIEXPORT jstring JNICALL Java_com_thewallet_CellframeModule_wrapWalletDetailsNative(JNIEnv *env, jobject thiz, jstring walletPath, jstring networkID, jstring pwd)
{
    const char *c_walletPath = (*env)->GetStringUTFChars(env, walletPath, 0);
    const char *c_networkID = (*env)->GetStringUTFChars(env, networkID, 0);
    const char *c_pwd = (*env)->GetStringUTFChars(env, pwd, 0);

    if (!c_walletPath || !c_networkID || !c_pwd) 
    {
        if (c_walletPath) (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        if (c_networkID) (*env)->ReleaseStringUTFChars(env, networkID, c_networkID);
        if (c_pwd) (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);

        return (*env)->NewStringUTF(env, "Error: Null input provided.");
    }

    dap_chain_wallet_t* result = dap_chain_wallet_open_file(c_walletPath, c_pwd, NULL);
    if(!result)
    {
        printf("Can't open wallet %s. Error %d (%s)\n\r", c_walletPath, errno, strerror(errno));
        
        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, networkID, c_networkID);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "Error opening wallet: %d (%s)", errno, strerror(errno));
        return (*env)->NewStringUTF(env, error_msg);
    }

    uint64_t l_net_id_ui64 = strtoull(c_networkID, NULL, 16);
    dap_chain_net_id_t l_net_id = {.uint64 = l_net_id_ui64};
    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(result, l_net_id);

    if (!l_addr) 
    {
        printf("Error: Address not found for network ID %s.\n", c_networkID);

        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, networkID, c_networkID);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);

        return (*env)->NewStringUTF(env, "Error: Address not found.");
    }

    const char*l_addr_str = dap_chain_addr_to_str_static(l_addr);
    if (!l_addr_str) 
    {
        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, networkID, c_networkID);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);

        return (*env)->NewStringUTF(env, "Error: Unable to convert address to string.");
    }

    jstring addr_jstring = (*env)->NewStringUTF(env, l_addr_str);

    (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
    (*env)->ReleaseStringUTFChars(env, networkID, c_networkID);
    (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);

    return addr_jstring;
}

JNIEXPORT jint JNICALL Java_com_thewallet_CellframeModule_wrapWalletCreateNative(JNIEnv *env, jobject thiz, jstring walletPath, jstring walletName, jstring pass, jstring sigType, jstring seed)
{
    const char *c_walletPath = (*env)->GetStringUTFChars(env, walletPath, 0);
    const char *c_walletName = (*env)->GetStringUTFChars(env, walletName, 0);
    const char *c_pass = (*env)->GetStringUTFChars(env, pass, 0);
    const char *c_sigType = (*env)->GetStringUTFChars(env, sigType, 0);
    const char *c_seed = (*env)->GetStringUTFChars(env, seed, 0);

    int result = s_wallet_create(c_walletPath, c_walletName, c_pass, c_sigType, c_seed);

    (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
    (*env)->ReleaseStringUTFChars(env, walletName, c_walletName);
    (*env)->ReleaseStringUTFChars(env, pass, c_pass);
    (*env)->ReleaseStringUTFChars(env, sigType, c_sigType);
    (*env)->ReleaseStringUTFChars(env, seed, c_seed);

    return (jint)result;
}

JNIEXPORT jstring JNICALL Java_com_thewallet_CellframeModule_wrapWalletSignNative(JNIEnv *env, jobject thiz, jstring walletPath, jstring pwd, jstring input)
{
    if (!walletPath || !pwd || !input) 
    {
        LOGE("One or more input strings are null");
        return (*env)->NewStringUTF(env, "Error: Null input strings");
    }

    LOGD("%s", "All variables are valid");

    const char *c_walletPath = (*env)->GetStringUTFChars(env, walletPath, 0);
    const char *c_pwd = (*env)->GetStringUTFChars(env, pwd, 0);
    const char *c_input = (*env)->GetStringUTFChars(env, input, 0);

    if (!c_walletPath || !c_pwd || !c_input) 
    {
        LOGE("Output strings are null");
        return (*env)->NewStringUTF(env, "Error: Output chars are NULL");
    }

    LOGD("Received walletPath: %s", c_walletPath);
    LOGD("Received input: %s", c_input);
    
    struct json_object *json_obj = json_tokener_parse(c_input);
    if(json_obj == NULL)
    {
        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
        (*env)->ReleaseStringUTFChars(env, input, c_input);

        LOGE("Error: JSON Object returned NULL");

        return (*env)->NewStringUTF(env, "Error: JSON Object returned NULL");
    }

    LOGD("%s", "Created the JSON object successfully!!!");

    dap_chain_datum_tx_t *l_tx = json_parse_input_tx(json_obj);
    if(!l_tx)
    {
        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
        (*env)->ReleaseStringUTFChars(env, input, c_input);

        LOGE("Error: Couldn't create tx for JSON object");

        return (*env)->NewStringUTF(env, "Error: Coudln't create tx for JSON obj");
    }

    LOGD("%s", "Created the TX successfully!!!");

    dap_chain_wallet_t *l_wallet = dap_chain_wallet_open_file(c_walletPath, c_pwd, NULL);
    if(!l_wallet)
    {
        dap_chain_datum_tx_delete(l_tx);

        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
        (*env)->ReleaseStringUTFChars(env, input, c_input);

        LOGE("Error: Wallet couldn't be opened");

        return (*env)->NewStringUTF(env, "Error: Wallet couldn't be opened");
    }

    LOGD("%s", "Created the wallet object successfully!!!");

    dap_enc_key_t *l_owner_key = dap_chain_wallet_get_key(l_wallet, 0);

    if(!l_owner_key)
    {
        dap_chain_datum_tx_delete(l_tx);

        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
        (*env)->ReleaseStringUTFChars(env, input, c_input);
        
        LOGE("Error: Couldn't retrieve key for wallet");

        return (*env)->NewStringUTF(env, "Error: Couldn't retrieve key for wallet");
    }

    LOGD("%s", "Created the owner key object successfully!!!");
    LOGD("Transaction pointer: %p", (void *)l_tx);
    LOGD("Key pointer: %p", (void *)l_owner_key);

    if (!l_owner_key) { 
        LOGE("Key pointer is NULL");
        return (*env)->NewStringUTF(env, "Error: Key pointer is NULL");
    }

    // Check (*a_tx)->tx_items
    if (!l_tx->tx_items) { 
        LOGE("Transaction items are NULL");
        return (*env)->NewStringUTF(env, "Error: Transaction items are NULL");
    }

    LOGD("TX ITEMS SIZE: %d", l_tx->header.tx_items_size);

    if (l_tx->header.tx_items_size == 0) { 
        LOGE("Transaction items size is zero");
        return (*env)->NewStringUTF(env, "Error: Transaction items size is zero");
    }

    int add_sign = dap_chain_datum_tx_add_sign_item(&l_tx, l_owner_key);
    LOGD("Add Sign return value: %d", add_sign);

    if(add_sign != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        dap_enc_key_delete(l_owner_key);

        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
        (*env)->ReleaseStringUTFChars(env, input, c_input);

        LOGE("Error: Issue adding sign item to datum tx");

        return (*env)->NewStringUTF(env, "Error: Issue addign sign item datum tx");
    }

    LOGD("%s", "Created the sign item successfully!!!");
    dap_enc_key_delete(l_owner_key);

    char *l_out = convert_tx_to_json_string(l_tx, true);
    if(!l_out)
    {
        dap_chain_datum_tx_delete(l_tx);

        (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
        (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
        (*env)->ReleaseStringUTFChars(env, input, c_input);

        LOGE("Error: Couldn't convert tx to JSON string");

        return (*env)->NewStringUTF(env, "Error: Couldn't convert tx to json string");
    }

    LOGD("%s", "Converted TX to json object successfully!!!");
    dap_chain_datum_tx_delete(l_tx);

    (*env)->ReleaseStringUTFChars(env, walletPath, c_walletPath);
    (*env)->ReleaseStringUTFChars(env, pwd, c_pwd);
    (*env)->ReleaseStringUTFChars(env, input, c_input);

    jstring result = (*env)->NewStringUTF(env, l_out);
    free(l_out);

    return result;
}
#endif