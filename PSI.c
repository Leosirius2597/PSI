#include "PSI.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ===========================
// 阶段 1：AES 会话密钥同步
// ===========================
//
// 云平台统一分发 (AES key + IV)，
// 各方用自己的 RSA 私钥解密后保存。
// 这样可以保证各方之间 AES 加解密完全互通。
//
// 调用示例
// Client *client_list[MAX_CLIENTS] = {clientA, clientB, clientC};
// psi_sync_all_clients(cloud, client_list, 3, verify, beaver);

void psi_sync_all_clients(PSICloud *cloud, Client *clients[], size_t client_count, Verify *verify, BeaverCloud *beaver)
{
    if (!cloud) {
        fprintf(stderr, "[PSI] 无效的云平台结构。\n");
        return;
    }

    printf("[PSI] 阶段 1：AES 会话密钥同步开始。\n");

    int client_num = client_count;   // 记录用户数量

    // =====================================================
    // 1️⃣ 分发给 Client
    // =====================================================
    
    for (size_t i = 0; i < client_num; i++){
        if (clients[i]) {           
            // RSA 加密+解密 发送 AES 密钥
            rsa_transfer_aes_key(&clients[i]->rsa_ctx, &clients[i]->aes_psi, &cloud->aes_internal);
            printf("[PSI] AES 会话密钥同步给 Client %d 成功。\n", i);
        }
    }
    
    // =====================================================
    // 2️⃣ 分发给 Verify
    // =====================================================
    if (verify) {    
        // RSA 加密+解密 发送 AES 密钥
        rsa_transfer_aes_key(&verify->rsa_ctx, &verify->aes_psi, &cloud->aes_internal);
        printf("[PSI] AES 会话密钥同步给 Verify 成功。\n");
    }

    // =====================================================
    // 3️⃣ 分发给 BeaverCloud
    // =====================================================
    if (beaver) {
        rsa_transfer_aes_key(&beaver->rsa_ctx, &beaver->aes_ctx, &cloud->aes_internal);
        printf("[PSI] AES 会话密钥同步给 BeaverCloud 成功。\n");

    }

    printf("[PSI] 阶段 1：AES 会话密钥同步完成。\n");
}


// ================================
// AES 加密并上传单个桶
// ================================
static void encrypt_and_send_bucket(const AESContext *aes_ctx, const Bucket *src_bucket, BucketSet *dest_set, size_t dest_index)
{
    unsigned char enc_buf[4096];
    int enc_len = 0;
    for (size_t i = 0; i < BUCKET_POLY_LEN; i++){
        aes_encrypt_mpz_buf(aes_ctx, src_bucket->coeffs[i], enc_buf, sizeof(enc_buf), &enc_len);
        aes_decrypt_mpz_buf(aes_ctx, enc_buf, enc_len, dest_set->buckets[dest_index].coeffs[i]);
    }
    
    // 继承桶 tag，用于云平台重建匹配
    aes_encrypt_mpz_buf(aes_ctx, src_bucket->tag, enc_buf, sizeof(enc_buf), &enc_len);
    aes_decrypt_mpz_buf(aes_ctx, enc_buf, enc_len, dest_set->buckets[dest_index].tag);
    
    printf("桶tag已加密上传。\n");
}


// ===============================
// 用户上传桶 （没有拆分）
// ===============================
void Clients_send_encrypted_buckets(Client *clients[], int client_count, PSICloud *cloud)
{

    if (!clients || !cloud) {
        fprintf(stderr, "[PSI] 参数错误。\n");
        return;
    }

    //中间参数
    unsigned char enc_buf[4096];
    int enc_len = 0;

    printf("[PSI] 用户开始发送桶...\n");

    for (size_t t = 0; t < client_count; t++){
        for (size_t i = 0; i < clients[t]->k; ++i) {
            size_t shuffled_idx = clients[t]->shuffle_table[i];
            Bucket *srcP = &clients[t]->H_P.buckets[i];
            Bucket *srcW = &clients[t]->H_W.buckets[i];
            Bucket *dstP = &cloud->users[clients[t]->user_id].H_P.buckets[shuffled_idx];
            Bucket *dstW = &cloud->users[clients[t]->user_id].H_W.buckets[shuffled_idx];

            // -----------------------
            // 按打乱表传输桶到云平台
            // -----------------------
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            
                // 将P桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, srcP->coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, dstP->coeffs[j]);
            
                //将W桶传输（顺序已经打乱）
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, srcW->coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, dstW->coeffs[j]);
            }

            // 将P桶的标识传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&clients[t]->aes_psi, srcP->tag, enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, dstP->tag);

        }
    }
    
    printf("[PSI] 用户桶发送完成（已打乱并存入云平台）。\n");
}

// ===========================================
// 验证方上传桶（没有拆分）
// ===========================================
void psi_send_encrypted_buckets_verify(Verify *verify, PSICloud *cloud)
{
    if (!verify || !cloud) {
        fprintf(stderr, "[PSI] 参数错误。\n");
        return;
    }

    //中间参数
    unsigned char enc_buf[4096];
    int enc_len = 0;

    printf("[PSI] 验证方开始发送桶...\n");

    for (size_t i = 0; i < verify->k; ++i) {
        size_t shuffled_idx = verify->shuffle_table[i];
        Bucket *srcP = &verify->H_P.buckets[i];
        Bucket *srcW = &verify->H_W.buckets[i];
        Bucket *dstP = &cloud->users[0].H_P.buckets[shuffled_idx];  // 验证方存到 cloud->users[0]
        Bucket *dstW = &cloud->users[0].H_W.buckets[shuffled_idx];
        
        // -----------------------
        // 按打乱表传输桶到云平台
        // -----------------------
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            
            // 将P桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, srcP->coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, dstP->coeffs[j]);
            
            //将W桶传输（顺序已经打乱）
            aes_encrypt_mpz_buf(&verify->aes_psi, srcW->coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, dstW->coeffs[j]);
        }

        // 将P桶的标识传输（顺序已经打乱）
        aes_encrypt_mpz_buf(&verify->aes_psi, srcP->tag, enc_buf, sizeof(enc_buf), &enc_len);
        aes_decrypt_mpz_buf(&cloud->aes_internal, enc_buf, enc_len, dstP->tag);
    }

    printf("[PSI] 验证方桶发送完成（已打乱并写入云平台）。\n");
}



// ===========================================================
//   BeaverCloud → 分发三元组给 用户/验证方 与 PSI 云平台
//   （带 AES 加密解密模拟 + 桶顺序打乱）
// ===========================================================
void beaver_cloud_distribute_to_client(BeaverCloud *cloud, Client *clients[], size_t client_count, PSICloud *psi_cloud, Verify *verify){

    printf("[BeaverCloud] 开始向用户/验证方与 PSI 云平台分发 Beaver 三元组...\n");

    //临时参数
    unsigned char enc_buf[4096];
    int enc_len;
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, (unsigned long)time(NULL));

    size_t k = cloud->original.beaver_A.count;

    // 初始化云平台内部的用户Beaver三元组部分
    for (size_t i = 0; i < client_count; i++){
        bucket_init(&psi_cloud->users[clients[i]->user_id].H_Beaver_a, k, cloud->m_bit);
        bucket_init(&psi_cloud->users[clients[i]->user_id].H_Beaver_b, k, cloud->m_bit);
        result_bucket_init(&psi_cloud->users[clients[i]->user_id].H_Beaver_c, k);
    }

    // 初始化云平台中验证方的Beaver三元组部分
    bucket_init(&psi_cloud->users[0].H_Beaver_a, k, cloud->m_bit);
    bucket_init(&psi_cloud->users[0].H_Beaver_b, k, cloud->m_bit);
    result_bucket_init(&psi_cloud->users[0].H_Beaver_c, k);

    // --- 临时随机拆分 ---
    Bucket A0, B0, A1, B1;
    Result_Bucket C0, C1;
    bucket_init((BucketSet*)&A0, 1, cloud->m_bit);
    bucket_init((BucketSet*)&B0, 1, cloud->m_bit);
    bucket_init((BucketSet*)&A1, 1, cloud->m_bit);
    bucket_init((BucketSet*)&B1, 1, cloud->m_bit);
    result_bucket_init((Result_BucketSet*)&C0, 1);
    result_bucket_init((Result_BucketSet*)&C1, 1);
    
    //遍历所有用户进行多项式三元组的分发
    for (size_t t = 0; t < client_count; t++){
        // 遍历每个桶生成并分发
        for (size_t i = 0; i < k; ++i) {
            Bucket *A = &cloud->original.beaver_A.buckets[i];
            Bucket *B = &cloud->original.beaver_B.buckets[i];
            Result_Bucket *C = &cloud->original.beaver_C.result_buckets[i];

            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_urandomb(A1.coeffs[j], state, cloud->m_bit);
                mpz_urandomb(B1.coeffs[j], state, cloud->m_bit);
                mpz_sub(A0.coeffs[j], A->coeffs[j], A1.coeffs[j]);
                mpz_sub(B0.coeffs[j], B->coeffs[j], B1.coeffs[j]);
            }

            for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
                mpz_urandomb(C1.coeffs[j], state, cloud->m_bit);
                mpz_sub(C0.coeffs[j], C->coeffs[j], C1.coeffs[j]);
            }
            
            // 用户拿到属于自己的多项式三元组
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j){
                
                //加密并传输A0
                aes_encrypt_mpz_buf(&cloud->aes_ctx, A0.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, clients[t]->H_Beaver_a.buckets[k].coeffs[j]);
                
                //加密并传输B0
                aes_encrypt_mpz_buf(&cloud->aes_ctx, B0.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);    
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, clients[t]->H_Beaver_b.buckets[k].coeffs[j]);
            }

            for (size_t j = 0; j < RESULT_POLY_LEN; ++j){
                
                //Beaver云平台侧加密待传输的 C0
                aes_encrypt_mpz_buf(&cloud->aes_ctx, C0.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);

                //用户侧解密并存储 C0
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, clients[t]->H_Beaver_c.result_buckets[k].coeffs[j]);

            }
            
            // --- 根据用户打乱表存入桶 ---
            size_t user_idx = clients[t]->shuffle_table[i];

            // PSI 云侧加密/解密
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j){
                
                //加密并传输A1
                aes_encrypt_mpz_buf(&cloud->aes_ctx, A1.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[user_idx].coeffs[j]);
                
                //加密并传输B1
                aes_encrypt_mpz_buf(&cloud->aes_ctx, B1.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[user_idx].coeffs[j]);
            }
            
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j){
                
                //Beaver云平台侧加密待传输的 C1
                aes_encrypt_mpz_buf(&cloud->aes_ctx, C1.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);

                //Psi云平台解密并存储 C1
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, psi_cloud->users[clients[t]->user_id].H_Beaver_c.result_buckets[user_idx].coeffs[j]);
            }
        }

    }
    printf("[BeaverCloud] 三元组分发完成（用户 + PSI 云平台）。\n");

    // 验证方拿到自己的Beaver多项式三元组
    // 遍历每个桶生成并分发
    for (size_t i = 0; i < k; ++i) {
        Bucket *A = &cloud->original.beaver_A.buckets[i];
        Bucket *B = &cloud->original.beaver_B.buckets[i];
        Result_Bucket *C = &cloud->original.beaver_C.result_buckets[i];

        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_urandomb(A1.coeffs[j], state, cloud->m_bit);
            mpz_urandomb(B1.coeffs[j], state, cloud->m_bit);
            mpz_sub(A0.coeffs[j], A->coeffs[j], A1.coeffs[j]);
            mpz_sub(B0.coeffs[j], B->coeffs[j], B1.coeffs[j]);
        }

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_urandomb(C1.coeffs[j], state, cloud->m_bit);
            mpz_sub(C0.coeffs[j], C->coeffs[j], C1.coeffs[j]);
        }
            
        // 验证方拿到属于自己的多项式三元组
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j){
                
            //加密并传输A0
            aes_encrypt_mpz_buf(&cloud->aes_ctx, A0.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, verify->H_Beaver_a.buckets[k].coeffs[j]);
                
            //加密并传输B0
            aes_encrypt_mpz_buf(&cloud->aes_ctx, B0.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);    
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, verify->H_Beaver_b.buckets[k].coeffs[j]);
        }

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j){
                
            //Beaver云平台侧加密待传输的 C0
            aes_encrypt_mpz_buf(&cloud->aes_ctx, C0.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);

            //用户侧解密并存储 C0
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, verify->H_Beaver_c.result_buckets[k].coeffs[j]);

        }
            
        // --- 根据验证方打乱表存入桶 ---
        size_t verify_idx = verify->shuffle_table[i];

        // PSI 云侧加密/解密
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j){
                
            //加密并传输A1
            aes_encrypt_mpz_buf(&cloud->aes_ctx, A1.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, psi_cloud->users[0].H_Beaver_a.buckets[verify_idx].coeffs[j]);
                
            //加密并传输B1
            aes_encrypt_mpz_buf(&cloud->aes_ctx, B1.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, psi_cloud->users[0].H_Beaver_b.buckets[verify_idx].coeffs[j]);
        }
            
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j){
                
            //Beaver云平台侧加密待传输的 C1
            aes_encrypt_mpz_buf(&cloud->aes_ctx, C1.coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);

            //Psi云平台解密并存储 C1
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, psi_cloud->users[0].H_Beaver_c.result_buckets[verify_idx].coeffs[j]);
        }
    }

    printf("[BeaverCloud] 三元组分发完成（验证方 + PSI 云平台）。\n");
    
    bucket_free((BucketSet*)&A0);
    bucket_free((BucketSet*)&B0);
    bucket_free((BucketSet*)&A1);
    bucket_free((BucketSet*)&B1);
    result_bucket_free((Result_BucketSet*)&C0);
    result_bucket_free((Result_BucketSet*)&C1);

    gmp_randclear(state);
    
}


// ===========================================================
//   FFT方法计算多个小模数下的多项式乘法（没改过）
// ===========================================================
void poly_modular_fft_compute(mpz_t *result, const mpz_t *polyA, const mpz_t *polyB, size_t lenA, size_t lenB, const ModSystem *mods, int op_type)
{
    size_t L = (op_type == 2) ? (lenA + lenB - 1) : lenA;
    size_t nmods = mods->m_count;

    mpz_t *remainders = malloc(sizeof(mpz_t) * nmods);
    mpz_t *moduli     = malloc(sizeof(mpz_t) * nmods);
    for (size_t i = 0; i < nmods; ++i) {
        mpz_init(remainders[i]);
        mpz_init_set(moduli[i], mods->m_list[i]);
    }

    // 临时数组存储每个小模数的结果
    mpz_t **partial_results = malloc(sizeof(mpz_t*) * nmods);
    for (size_t i = 0; i < nmods; ++i) {
        partial_results[i] = malloc(sizeof(mpz_t) * L);
        for (size_t j = 0; j < L; ++j)
            mpz_init(partial_results[i][j]);
    }

    // 逐小模数计算
    #pragma omp parallel for
    for (size_t idx = 0; idx < nmods; ++idx) {
        unsigned long m = mpz_get_ui(mods->m_list[idx]);

        // 转为 double 形式
        long double *A = calloc(lenA, sizeof(long double));
        long double *B = calloc(lenB, sizeof(long double));
        long double *Res = calloc(L, sizeof(long double));

        for (size_t j = 0; j < lenA; ++j)
            A[j] = fmodl((long double)mpz_fdiv_ui(polyA[j], m), (long double)m);
        for (size_t j = 0; j < lenB; ++j)
            B[j] = fmodl((long double)mpz_fdiv_ui(polyB[j], m), (long double)m);

        // 运算
        if (op_type == 0) {
            for (size_t j = 0; j < lenA; ++j)
                Res[j] = fmodl(A[j] + B[j], m);
        } else if (op_type == 1) {
            for (size_t j = 0; j < lenA; ++j)
                Res[j] = fmodl(A[j] - B[j] + m, m);
        } else if (op_type == 2) {
            poly_multiply_scaled(A, lenA, B, lenB, (long double)m, Res);
            for (size_t j = 0; j < L; ++j)
                Res[j] = fmodl(Res[j], m);
        }

        // 转回 GMP
        for (size_t j = 0; j < L; ++j)
            mpz_set_ui(partial_results[idx][j], (unsigned long)Res[j]);

        free(A); free(B); free(Res);
    }

    // 合并每个系数（CRT）
    for (size_t j = 0; j < L; ++j) {
        for (size_t i = 0; i < nmods; ++i)
            mpz_set(remainders[i], partial_results[i][j]);

        crt_combine(result[j], mods->M, remainders, moduli, nmods);
    }

    // 清理内存
    for (size_t i = 0; i < nmods; ++i) {
        for (size_t j = 0; j < L; ++j)
            mpz_clear(partial_results[i][j]);
        free(partial_results[i]);
        mpz_clear(remainders[i]);
        mpz_clear(moduli[i]);
    }
    free(partial_results);
    free(remainders);
    free(moduli);
}

// ===========================================================
//   计算多项式Beaver三元组结果
// ===========================================================
void beaver_compute_multiplication(Client *clients[], int client_count, PSICloud *psi_cloud, Verify *verify, const ModSystem *mods){

    //获得表长
    size_t k = clients[0]->k;
    
    //初始化逆打乱表
    size_t *inv_shuffle = malloc(sizeof(size_t) * k);

    printf("[Beaver] 开始计算 Beaver 乘法阶段...\n");

    //设置中间态
    unsigned char enc_buf[4096];
    int enc_len = 0;

    //遍历每个用户
    for (size_t t = 0; t < client_count; t++){
        // 初始化结果桶
        result_bucket_init(&clients[t]->PSI_result, k);
        result_bucket_init(&psi_cloud->users[clients[t]->user_id].PSI_result, k);

         // ---------- Step 0: 构造逆打乱表 ----------
        for (size_t i = 0; i < k; ++i)
            inv_shuffle[clients[t]->shuffle_table[i]] = i;
        
        // ---------- Step 1: 用户计算 d0(x), e0(x) ----------
        mpz_t **d0 = malloc(sizeof(mpz_t*) * k);
        mpz_t **e0 = malloc(sizeof(mpz_t*) * k);
        for (size_t i = 0; i < k; ++i) {
            d0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            e0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_init(d0[i][j]);
                mpz_init(e0[i][j]);
                mpz_sub(d0[i][j], clients[t]->H_P.buckets[i].coeffs[j], clients[t]->H_Beaver_a.buckets[i].coeffs[j]);
                mpz_sub(e0[i][j], clients[t]->H_W.buckets[i].coeffs[j], clients[t]->H_Beaver_b.buckets[i].coeffs[j]);
                mpz_mod(d0[i][j], d0[i][j], mods->M);
                mpz_mod(e0[i][j], e0[i][j], mods->M);
            }
        }



        // ---------- Step 2: 打乱并“发送” d0,e0 到云端 ----------
        mpz_t **recv_d0 = malloc(sizeof(mpz_t*) * k);
        mpz_t **recv_e0 = malloc(sizeof(mpz_t*) * k);
        for (size_t i = 0; i < k; ++i) {
            size_t s = clients[t]->shuffle_table[i];
            recv_d0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            recv_e0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);

            // 将d0 和 e0打乱顺序后 aes加密传输
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                
                mpz_init(recv_d0[s][j]);
                mpz_init(recv_e0[s][j]);
                // 加密传输d0
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, d0[i][j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, recv_d0[s][j]);

                // 加密传输e0
                aes_encrypt_mpz_buf(&clients[t]->aes_psi, e0[i][j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, recv_e0[s][j]);
            }   
        }

        // ---------- Step 3: 云端计算 d(x), e(x) ----------
        mpz_t **d_cloud = malloc(sizeof(mpz_t*) * k);
        mpz_t **e_cloud = malloc(sizeof(mpz_t*) * k);
        for (size_t s = 0; s < k; ++s) {
            Bucket *P1 = &psi_cloud->users[clients[t]->user_id].H_P.buckets[s];
            Bucket *W1 = &psi_cloud->users[clients[t]->user_id].H_W.buckets[s];
            Bucket *a1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[s];
            Bucket *b1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[s];

            d_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            e_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);

            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_init(d_cloud[s][j]);
                mpz_init(e_cloud[s][j]);
                mpz_sub(d_cloud[s][j], P1->coeffs[j], a1->coeffs[j]); // d1
                mpz_sub(e_cloud[s][j], W1->coeffs[j], b1->coeffs[j]); // e1
                mpz_add(d_cloud[s][j], d_cloud[s][j], recv_d0[s][j]); // + d0’
                mpz_add(e_cloud[s][j], e_cloud[s][j], recv_e0[s][j]); // + e0’
                mpz_mod(d_cloud[s][j], d_cloud[s][j], mods->M);
                mpz_mod(e_cloud[s][j], e_cloud[s][j], mods->M);
            }
        }

        
        // ---------- Step 4: 用户端逆打乱恢复 d,e ----------
        mpz_t **d_user = malloc(sizeof(mpz_t*) * k);
        mpz_t **e_user = malloc(sizeof(mpz_t*) * k);
        for (size_t i = 0; i < k; ++i) {
            size_t s = clients[t]->shuffle_table[i];
            d_user[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            e_user[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
            
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                
                mpz_inits(d_user[i][j], e_user[i][j], NULL);

                // 加密传输d
                aes_encrypt_mpz_buf(&psi_cloud->aes_internal, d_cloud[s][j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, d_user[i][j]);

                // 加密传输e
                aes_encrypt_mpz_buf(&psi_cloud->aes_internal, e_user[i][j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&clients[t]->aes_psi, enc_buf, enc_len, e_user[i][j]);
            }
        }
    
        // ---------- Step 5: 各方计算 PSI 结果 ----------
        for (size_t i = 0; i < k; ++i) {
            // 本地侧
            Bucket *a0 = &clients[t]->H_Beaver_a.buckets[i];
            Bucket *b0 = &clients[t]->H_Beaver_b.buckets[i];
            Result_Bucket *c0 = &clients[t]->H_Beaver_c.result_buckets[i];
            Result_Bucket *res_local = &clients[t]->PSI_result.result_buckets[i];

            poly_modular_fft_compute(res_local->coeffs, d_user[i], b0->coeffs,
                                 BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            poly_modular_fft_compute(res_local->coeffs, e_user[i], a0->coeffs,
                                 BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
                mpz_add(res_local->coeffs[j], res_local->coeffs[j], c0->coeffs[j]);
                mpz_mod(res_local->coeffs[j], res_local->coeffs[j], mods->M);
            }
        }

        // ---------- Step 5: 云端侧计算 PSI 结果（d,e 重新打乱后对齐） ----------
    
        // 云端在打乱顺序下计算结果
        for (size_t s = 0; s < k; ++s) {
            Bucket *a1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_a.buckets[s];
            Bucket *b1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_b.buckets[s];
            Result_Bucket *c1 = &psi_cloud->users[clients[t]->user_id].H_Beaver_c.result_buckets[s];
            Result_Bucket *res_cloud = &psi_cloud->users[clients[t]->user_id].PSI_result.result_buckets[s];

            // 重新初始化结果桶
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
                mpz_set_ui(res_cloud->coeffs[j], 0);

            poly_modular_fft_compute(res_cloud->coeffs, d_cloud[s], b1->coeffs,
                                 BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            poly_modular_fft_compute(res_cloud->coeffs, e_cloud[s], a1->coeffs,
                                 BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
            for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
                mpz_add(res_cloud->coeffs[j], res_cloud->coeffs[j], c1->coeffs[j]);
                mpz_mod(res_cloud->coeffs[j], res_cloud->coeffs[j], mods->M);
            }
            mpz_set(res_cloud->tag, c1->tag); // tag 同步
        }   
        printf("[Beaver] 云平台 PSI 结果计算完成。\n");
        
        // 清理
        free(inv_shuffle);
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_clear(d0[i][j]);
                mpz_clear(e0[i][j]);
                mpz_clear(d_user[i][j]);
                mpz_clear(e_user[i][j]);
            }
            free(d0[i]); free(e0[i]); free(d_user[i]); free(e_user[i]);
        }
    
    }

    printf("[Verify] 开始计算 Beaver 乘法阶段...\n");
    
    if (! verify || !psi_cloud || !mods) {
        fprintf(stderr, "[Verify] 参数错误。\n");
        return;
    }

    // 初始化结果桶
    result_bucket_init(&verify->result_user, k);
    result_bucket_init(&psi_cloud->users[0].PSI_result, k);
    
    // ---------- Step 0: 构造逆打乱表 ----------
    for (size_t i = 0; i < k; ++i)
        inv_shuffle[verify->shuffle_table[i]] = i;
    
    // ---------- Step 1: 验证方计算 d0(x), e0(x) ----------
    mpz_t **d0 = malloc(sizeof(mpz_t*) * k);
    mpz_t **e0 = malloc(sizeof(mpz_t*) * k);
    for (size_t i = 0; i < k; ++i) {
        d0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        e0[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(d0[i][j]);
            mpz_init(e0[i][j]);
            mpz_sub(d0[i][j], verify->H_P.buckets[i].coeffs[j], verify->H_Beaver_a.buckets[i].coeffs[j]);
            mpz_sub(e0[i][j], verify->H_W.buckets[i].coeffs[j], verify->H_Beaver_b.buckets[i].coeffs[j]);
            mpz_mod(d0[i][j], d0[i][j], mods->M);
            mpz_mod(e0[i][j], e0[i][j], mods->M);
        }
    }

    // ---------- Step 2: 打乱并“发送” d0,e0 到云端 ----------
    mpz_t **recv_d0 = malloc(sizeof(mpz_t*) * k);
    mpz_t **recv_e0 = malloc(sizeof(mpz_t*) * k);
    for (size_t i = 0; i < k; ++i) {
        
        //生成打乱顺序
        size_t s = verify->shuffle_table[i];
        recv_d0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        recv_e0[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            
            //初始化接收数组
            mpz_inits(recv_d0[s][j], recv_e0[s][j], NULL);
            
            //加密发送d0
            aes_encrypt_mpz_buf(&verify->aes_psi, d0[i][j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, recv_d0[s][j]);

            //加密发送e0
            aes_encrypt_mpz_buf(&verify->aes_psi, e0[i][j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&psi_cloud->aes_internal, enc_buf, enc_len, recv_e0[s][j]);
        }
    }
    
    // ---------- Step 3: 云端计算 d(x), e(x) ----------
    mpz_t **d_cloud = malloc(sizeof(mpz_t*) * k);
    mpz_t **e_cloud = malloc(sizeof(mpz_t*) * k);
    for (size_t s = 0; s < k; ++s) {
        Bucket *P1 = &psi_cloud->users[0].H_P.buckets[s];
        Bucket *W1 = &psi_cloud->users[0].H_W.buckets[s];
        Bucket *a1 = &psi_cloud->users[0].H_Beaver_a.buckets[s];
        Bucket *b1 = &psi_cloud->users[0].H_Beaver_b.buckets[s];

        d_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        e_cloud[s] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);

        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(d_cloud[s][j]);
            mpz_init(e_cloud[s][j]);
            mpz_sub(d_cloud[s][j], P1->coeffs[j], a1->coeffs[j]); // d1
            mpz_sub(e_cloud[s][j], W1->coeffs[j], b1->coeffs[j]); // e1
            mpz_add(d_cloud[s][j], d_cloud[s][j], recv_d0[s][j]); // + d0’
            mpz_add(e_cloud[s][j], e_cloud[s][j], recv_e0[s][j]); // + e0’
            mpz_mod(d_cloud[s][j], d_cloud[s][j], mods->M);
            mpz_mod(e_cloud[s][j], e_cloud[s][j], mods->M);
        }
    }

    // ---------- Step 4: 验证方逆打乱恢复 d,e ----------
    mpz_t **d_user = malloc(sizeof(mpz_t*) * k);
    mpz_t **e_user = malloc(sizeof(mpz_t*) * k);
    for (size_t i = 0; i < k; ++i) {
        size_t s = verify->shuffle_table[i];
        d_user[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        e_user[i] = malloc(sizeof(mpz_t) * BUCKET_POLY_LEN);
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            
            // 初始化接收桶
            mpz_inits(d_user[i][j], e_user[i][j], NULL);

            // 加密并传输d
            aes_encrypt_mpz_buf(&psi_cloud->aes_internal, d_cloud[s][j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, d_user[i][j]);

            // 加密并传输e
            aes_encrypt_mpz_buf(&psi_cloud->aes_internal, e_cloud[s][j], enc_buf, sizeof(enc_buf), &enc_len);
            aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, e_user[i][j]);
        }
    }
        
    // ---------- Step 5: 验证方计算 PSI 结果 ----------
    for (size_t i = 0; i < k; ++i) {
        // 验证方侧
        Bucket *a0 = &verify->H_Beaver_a.buckets[i];
        Bucket *b0 = &verify->H_Beaver_b.buckets[i];
        Result_Bucket *c0 = &verify->H_Beaver_c.result_buckets[i];
        Result_Bucket *res_local = &verify->result_user.result_buckets[i];

        poly_modular_fft_compute(res_local->coeffs, d_user[i], b0->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        
        poly_modular_fft_compute(res_local->coeffs, e_user[i], a0->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_add(res_local->coeffs[j], res_local->coeffs[j], c0->coeffs[j]);
            mpz_mod(res_local->coeffs[j], res_local->coeffs[j], mods->M);
        }
    }

    // ---------- Step 6: 云端侧计算 PSI 结果（d,e 重新打乱对齐） ----------
    
    for (size_t s = 0; s < k; ++s) {
        Bucket *a1 = &psi_cloud->users[0].H_Beaver_a.buckets[s];
        Bucket *b1 = &psi_cloud->users[0].H_Beaver_b.buckets[s];
        Result_Bucket *c1 = &psi_cloud->users[0].H_Beaver_c.result_buckets[s];
        Result_Bucket *res_cloud = &psi_cloud->users[0].PSI_result.result_buckets[s];

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
            mpz_set_ui(res_cloud->coeffs[j], 0);

        poly_modular_fft_compute(res_cloud->coeffs, d_cloud[s], b1->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        poly_modular_fft_compute(res_cloud->coeffs, e_cloud[s], a1->coeffs, BUCKET_POLY_LEN, BUCKET_POLY_LEN, mods, 2);
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_add(res_cloud->coeffs[j], res_cloud->coeffs[j], c1->coeffs[j]);
            mpz_mod(res_cloud->coeffs[j], res_cloud->coeffs[j], mods->M);
        }
        mpz_set(res_cloud->tag, c1->tag);
    
    // ---------- 清理内存 ----------
        free(inv_shuffle);
        for (size_t i = 0; i < k; ++i) {
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_clear(d0[i][j]);
                mpz_clear(e0[i][j]);
                mpz_clear(d_user[i][j]);
                mpz_clear(e_user[i][j]);
            }
            free(d0[i]); free(e0[i]); free(d_user[i]); free(e_user[i]);
        }

        for (size_t s = 0; s < k; ++s) {
            for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
                mpz_clear(d_cloud[s][j]);
                mpz_clear(e_cloud[s][j]);
            }
            free(d_cloud[s]); free(e_cloud[s]);
        }
        free(d_cloud);
        free(e_cloud);
    
    }

    
    printf("[Beaver] Beaver 乘法阶段完成。\n");
    
}


// ===========================================================
//   验证方 → 分发 AES 密钥给所有用户
// ===========================================================
void verify_distribute_aes_key(Verify *verify, Client *clients[], int client_count){
    
    if (!verify || !clients) {
        fprintf(stderr, "[Verify] AES 密钥分发失败：参数错误。\n");
        return;
    }

    printf("[Verify] 开始生成并分发新的 AES 密钥（结果阶段通信使用）...\n");

    // ---------- Step 1. 验证方生成新的 AES 密钥 ----------
    aes_generate_mem(&verify->aes_verify);
    printf("[Verify] 已生成新的 AES 密钥，用于结果阶段通信。\n");

    // ---------- Step 2. 遍历每个用户 ----------
    for (size_t i = 0; i < client_count; ++i) {
        Client *cli = clients[i];
        if (!cli) continue;

        // RSA 加密密钥并分发
        rsa_transfer_aes_key(&cli->rsa_ctx, &cli->aes_verify, &verify->aes_verify);
    }

    printf("[Verify] 所有用户均已收到结果阶段 AES 密钥。\n");
}

// ===========================================================
//  发送 PSI 结果到验证方
// ===========================================================
void send_result_to_verify(Client *clients[], int client_count,  PSICloud *psi_cloud, Verify *verify, const ModSystem *mods)
{
    if (!clients || !psi_cloud || !verify || !mods) {
        fprintf(stderr, "[Client→Verify] 参数错误。\n");
        return;
    }

    // 加密中间态
    unsigned char enc_buf[4096];
    int enc_len;
    //中转中间态
    Result_BucketSet temp_result;

    size_t k = clients[0]->k;
    // 初始化中转中间态
    result_bucket_init(&temp_result, k);
    

    for (size_t t = 0; t < client_count; t++){
        
        printf("[Client→Verify] 用户 %lu 开始发送 PSI 结果桶...\n", (unsigned long)clients[t]->user_id);
            
        // ---------- 用户将结果发送给验证方 ----------
        for (size_t i = 0; i < k; i++){
            for (size_t j = 0; j < RESULT_POLY_LEN; j++){
                
                //将结果传进中间态
                aes_encrypt_mpz_buf(&clients[t]->aes_verify, clients[t]->PSI_result.result_buckets[i].coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&verify->aes_verify, enc_buf, enc_len, temp_result.result_buckets[i].coeffs[j]);
                
                //验证方将结果加和到自己的结果中
                mpz_add(verify->result_user.result_buckets[i].coeffs[j], verify->result_user.result_buckets[i].coeffs[j], temp_result.result_buckets[i].coeffs[j]);

                //验证方进行mod M
                mpz_mod(verify->result_user.result_buckets[i].coeffs[j], verify->result_user.result_buckets[i].coeffs[j], mods->M);

            }  
        } 
        printf("[Client→Verify] 用户 %lu 的结果桶已成功传输并合并（模 M）。\n", (unsigned long)clients[t]->user_id);
    }

    printf("[PSI→Verify] 云平台开始向验证方发送云平台计算 PSI 结果...\n");

    // 遍历各个用户
    for (size_t t = 0; t < client_count; t++){
        
        // ---------- 逆打乱桶顺序 ----------
        size_t *inv_shuffle = malloc(sizeof(size_t) * k);
        for (size_t i = 0; i < k; ++i)
            inv_shuffle[clients[t]->shuffle_table[i]] = i;
        
        for (size_t i = 0; i < k; i++){
            size_t original_idx = inv_shuffle[i]; // 云端桶 s 对应的用户原顺序位置

            Result_Bucket *res_cloud_user = &psi_cloud->users[clients[t]->user_id].PSI_result.result_buckets[i];
            Result_Bucket *res_verify     = &verify->result_cloud.result_buckets[original_idx];

            for (size_t j = 0; j < RESULT_POLY_LEN; j++){
                
                // 将计算结果重整顺序后放入加密中间态
                aes_encrypt_mpz_buf(&psi_cloud->aes_internal, res_cloud_user->coeffs[j], enc_buf, sizeof(enc_buf), &enc_len);
                aes_decrypt_mpz_buf(&verify->aes_psi, enc_buf, enc_len, temp_result.result_buckets[original_idx].coeffs[j]);
                
                // 验证方取回并模运算
                mpz_add(res_verify->coeffs[j], res_verify->coeffs[j], temp_result.result_buckets[original_idx].coeffs[j]);
                mpz_mod(res_verify->coeffs[j], res_verify->coeffs[j], mods->M);

            }
            
        }
        free(inv_shuffle);
    }
   
    printf("[PSI→Verify] 所有云端结果均已成功传输并合并至验证方。\n");
}


// ===========================================================
//   Verify → 合并结果并检查交集
// ===========================================================
void verify_merge_and_check_intersection(Verify *verify,const ModSystem *mods){
    if (!verify || !mods) {
        fprintf(stderr, "[Verify] 参数错误。\n");
        return;
    }

    printf("[Verify] 开始合并结果并检查交集...\n");

    size_t k = verify->k;
    size_t data_len = 1UL << verify->n;

    // ---------- Step 1. 合并 result_user 与 result_cloud ----------
    if (verify->result_merged.result_buckets == NULL)
        result_bucket_init(&verify->result_merged, k);

    for (size_t i = 0; i < k; ++i) {
        Result_Bucket *merged = &verify->result_merged.result_buckets[i];
        Result_Bucket *user   = &verify->result_user.result_buckets[i];
        Result_Bucket *cloud  = &verify->result_cloud.result_buckets[i];

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_add(merged->coeffs[j], user->coeffs[j], cloud->coeffs[j]);
            mpz_mod(merged->coeffs[j], merged->coeffs[j], mods->M);
        }

        mpz_set(merged->tag, user->tag);
    }

    printf("[Verify] 合并完成，开始检查交集...\n");

    // ---------- Step 2. 检查交集 ----------
    size_t intersection_count = 0;

    

    for (size_t i = 0; i < data_len; ++i) {
        mpz_t s_prime, eval;
        mpz_inits(s_prime, eval, NULL);

        // 计算哈希与桶索引
        uint64_t h = hash48_compute(verify->data[i]);
        size_t bucket_idx = h % k;

        // 构造带哈希的数据 s' = (s << 48) | h(s)
        hash48_append(s_prime, verify->data[i]);

        // 多项式 P(x) = 0 检查
        Result_Bucket *poly = &verify->result_merged.result_buckets[bucket_idx];
        mpz_set_ui(eval, 0);
        mpz_t power, term;
        mpz_inits(power, term, NULL);
        mpz_set_ui(power, 1);

        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            // term = coeff[j] * power mod M
            mpz_mul(term, poly->coeffs[j], power);
            mpz_add(eval, eval, term);
            mpz_mod(eval, eval, mods->M);
            mpz_mul(power, power, s_prime);
            mpz_mod(power, power, mods->M);
        }

        // 若 P(s') ≡ 0 (mod M)，则交集成立
        if (mpz_sgn(eval) == 0) {
            gmp_printf("  → 交集元素: s = %Zd  (hash = %lu, 桶 = %zu)\n",
                       verify->data[i], h, bucket_idx);
            intersection_count++;
        }

        mpz_clears(s_prime, eval, power, term, NULL);
    }

    printf("[Verify] 交集检查完成，共发现 %zu 个交集元素。\n", intersection_count);
}

