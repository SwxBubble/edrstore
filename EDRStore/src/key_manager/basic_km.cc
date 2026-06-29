/**
 * @file basicKM.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief
 * @version 0.1
 * @date 2022-04-23
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "../../include/key_manager/basic_km.h"

BasicKM::BasicKM(SSLConnection* km_channel) {
    km_channel_ = km_channel;

    send_chunk_batch_size_ = config.GetSendChunkBatchSize();
    memset(global_secret_, 1, CHUNK_HASH_SIZE);
    memset(global_padding_secret_, 2, CHUNK_HASH_SIZE);
    crypto_util_ = new CryptoUtil(CIPHER_TYPE, HASH_TYPE);

    feature_index_ = new OdessSubfeatureIndex();
}

BasicKM::~BasicKM() {
    const uint64_t total_entries = feature_index_->TotalEntries();
    delete crypto_util_;
    delete feature_index_;
    fprintf(stderr, "========BasicKM Info========\n");
    fprintf(stderr, "key gen num: %lu\n", _total_key_gen_num);
    fprintf(stderr, "similar chunk num: %lu\n", _total_similar_chunk_num);
    fprintf(stderr, "total key index entries: %lu (12 per non-similar chunk)\n",
        total_entries);
    fprintf(stderr, "============================\n");
}

void BasicKM::Run(SSL* key_client_ssl) {
    tool::Logging(my_name_.c_str(), "the main thread is running.\n");
    uint32_t recv_size = 0;
    string client_ip;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    // the recv buffer
    SendMsgBuffer_t recv_req_buf;
    recv_req_buf.send_buf = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        send_chunk_batch_size_ * sizeof(KeyGenReq_t));
    recv_req_buf.header = (NetworkHead_t*) recv_req_buf.send_buf;
    recv_req_buf.data_buf = recv_req_buf.send_buf + sizeof(NetworkHead_t);
    uint32_t client_id = 0;

    // the send buffer
    SendMsgBuffer_t send_key_buf;
    send_key_buf.send_buf = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        send_chunk_batch_size_ * sizeof(KeyGenRet_t));
    send_key_buf.header = (NetworkHead_t*) send_key_buf.send_buf;
    send_key_buf.data_buf = send_key_buf.send_buf + sizeof(NetworkHead_t);

    struct timeval stime;
    struct timeval etime;
    struct timeval s_total_time;
    struct timeval e_total_time;
    double total_running_time = 0;
    double total_proc_time = 0;

    gettimeofday(&s_total_time, NULL);
    // -------- main process ---------

    // Buffer for deterministic key derivation: global_secret || features[0..11].
    static const size_t kDeriveBufSize = CHUNK_HASH_SIZE +
        sizeof(uint64_t) * SUB_FEATURE_PER_CHUNK;
    uint8_t derive_buf[kDeriveBufSize] = {0};
    memcpy(derive_buf, global_secret_, CHUNK_HASH_SIZE);

    while (true) {
        if (!km_channel_->ReceiveData(key_client_ssl, recv_req_buf.send_buf,
            recv_size)) {
            tool::Logging(my_name_.c_str(), "client closed socket connect, thread exit now.\n");
            km_channel_->GetClientIp(client_ip, key_client_ssl);
            km_channel_->ClearAcceptedClientSd(key_client_ssl);
            client_id = recv_req_buf.header->client_id;
            break;
        } else {
            gettimeofday(&stime, NULL);
            if (recv_req_buf.header->msg_type != CLIENT_KEY_GEN) {
                tool::Logging(my_name_.c_str(), "wrong key gen req type.\n");
                exit(EXIT_FAILURE);
            }

            uint32_t recv_fp_num = recv_req_buf.header->cur_item_num;

            KeyGenReq_t* cur_key_gen_req = (KeyGenReq_t*) recv_req_buf.data_buf;
            KeyGenRet_t* cur_key_gen_ret = (KeyGenRet_t*) send_key_buf.data_buf;
            for (size_t i = 0; i < recv_fp_num; i++) {
                // 12-table voting lookup. Top-1 wins because the key server must
                // mint exactly one key per chunk; the storage server independently
                // ranks top-K on cipher features at delta-encode time.
                std::vector<std::string> candidates =
                    feature_index_->QueryTopK(cur_key_gen_req->features);

                if (!candidates.empty()) {
                    // Reuse the existing key_seed of the best match so the new
                    // chunk encrypts under the same key as its base, preserving
                    // post-encryption similarity for delta compression.
                    memcpy(cur_key_gen_ret->key_seed,
                        candidates[0].data(), CHUNK_HASH_SIZE);
                    _total_similar_chunk_num++;
                } else {
                    // NON_SIMILAR: derive a fresh key_seed deterministically
                    // from (global_secret || features[0..11]) and claim it in
                    // the inverted index for future similar chunks.
                    memcpy(derive_buf + CHUNK_HASH_SIZE,
                        cur_key_gen_req->features,
                        sizeof(uint64_t) * SUB_FEATURE_PER_CHUNK);
                    crypto_util_->GenerateHash(md_ctx, derive_buf,
                        kDeriveBufSize, cur_key_gen_ret->key_seed);

                    std::string seed_str((char*)cur_key_gen_ret->key_seed,
                        CHUNK_HASH_SIZE);
                    feature_index_->Insert(cur_key_gen_req->features, seed_str);
                }

                cur_key_gen_req++;
                cur_key_gen_ret++;
            }

            gettimeofday(&etime, NULL);
            total_proc_time += tool::GetTimeDiff(stime, etime);

            // send the key gen result back to the client
            send_key_buf.header->size = recv_fp_num * sizeof(KeyGenRet_t);
            send_key_buf.header->cur_item_num = recv_fp_num;
            send_key_buf.header->msg_type = KEY_MANAGER_KEY_GEN_REPLY;
            if (!km_channel_->SendData(key_client_ssl, send_key_buf.send_buf,
                sizeof(NetworkHead_t) + send_key_buf.header->size)) {
                // Client died mid-batch (typical when the storage server
                // killed its session). Drop the reply, exit this thread
                // cleanly so other clients can continue to be served.
                tool::Logging(my_name_.c_str(),
                    "send the key gen errors; dropping client.\n");
                km_channel_->GetClientIp(client_ip, key_client_ssl);
                km_channel_->ClearAcceptedClientSd(key_client_ssl);
                client_id = recv_req_buf.header->client_id;
                break;
            }
            _total_key_gen_num += recv_fp_num;
        }
    }

    gettimeofday(&e_total_time, NULL);
    total_running_time += tool::GetTimeDiff(s_total_time, e_total_time);

    EVP_MD_CTX_free(md_ctx);
    free(recv_req_buf.send_buf);
    free(send_key_buf.send_buf);
    tool::Logging(my_name_.c_str(), "thread exits for %s, ID: %u, total process time: %lf\n",
        client_ip.c_str(), client_id, total_proc_time);

    return ;
}
