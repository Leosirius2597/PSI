
#include "PSI.h"
#include "client.h"
#include "PSI_Cloud.h"
#include "Verify.h"
#include "Beaver_Cloud.h"
#include <time.h>

// 定义数据比特位数
#define DATA_BIT 40

int main(){

    // 生成计时点
    clock_t t_init_begin, t_init_end, t_outsrc_begin, t_outsrc_end, t_compute_begin, t_compute_end, t_check_begin, t_check_end;

    // 用户数量
    int client_count = 1;

    // 数据集大小
    int DATASET_NUM;

    // 桶数量
    int BUCKET_NUM;

    // 不同数据集大小对应的桶数量
    int dataset_sizes[10] = {10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    int bucket_counts[10] = {3, 6, 12, 23, 45, 91, 182, 365, 733, 1474, 2962};
    
    for (size_t i = 0; i < 10; i++){
    
        DATASET_NUM = dataset_sizes[i];
        BUCKET_NUM = bucket_counts[i];
        
        // 生成PSI云平台 结构
        PSICloud psi_cloud;

        //生成验证方结构
        Verify verify;

        // 生成Beaver云平台结构
        BeaverCloud beaver_cloud;

        // 生成客户端数组
        Client **clients = malloc(sizeof(Client*) * client_count);

        
        // 生成模数
        ModSystem mods;

        //初始化模数
        modsystem_init_auto(&mods, 40, 123);

        t_init_begin = clock();
        // 初始化客户端
        for (size_t i = 0; i < client_count; ++i) {
            clients[i] = malloc(sizeof(Client));
            client_init(clients[i], DATASET_NUM, DATA_BIT, BUCKET_NUM, 123, i+1);
            client_build_buckets(clients[i], mods.M);
            client_insert_dataset(clients[i], mods.M);
        }

        t_init_end = clock();
        printf("单个用户初始化耗时：%.3f 秒\n", (double)(t_init_end - t_init_begin)/CLOCKS_PER_SEC / client_count);

        // 初始化验证方
        verify_init(&verify, DATASET_NUM, DATA_BIT, BUCKET_NUM, 456);
        verify_build_buckets(&verify, mods.M);
        verify_insert_dataset(&verify, mods.M);

        // 初始化PSI云平台
        psi_cloud_init(&psi_cloud, client_count+1, BUCKET_NUM, DATA_BIT, 123);

        // 初始化Beaver云平台
        beaver_cloud_init(&beaver_cloud, DATA_BIT, 123, BUCKET_NUM);
        
        

        // 进行PSI
        // 第一步，PSI云平台将AES密钥发送给各方
        psi_sync_all_clients(&psi_cloud, clients, client_count, &verify, &beaver_cloud);

        // 第二步，Beaver云平台分发多项式Beaver三元组
        beaver_cloud_distribute_to_client(&beaver_cloud, clients, client_count, &psi_cloud, &verify, mods.M);

        t_outsrc_begin = clock();
        // 第三步，用户上传桶
        Clients_send_encrypted_buckets(clients, client_count, &psi_cloud, mods.M);
    
        // 第四步，验证方上传桶
        psi_send_encrypted_buckets_verify(&verify, &psi_cloud, mods.M);

        t_outsrc_end = clock();
        printf("托管阶段耗时：%.3f 秒\n", (double)(t_outsrc_end - t_outsrc_begin)/CLOCKS_PER_SEC);
        
        t_compute_begin = clock();
        // 第五步，计算多项式Beaver三元组结果
        beaver_compute_multiplication(clients, client_count, &psi_cloud, &verify, &mods);

        t_compute_end = clock();
        printf("PSI计算阶段总耗时：%.3f 秒\n", (double)(t_compute_end - t_compute_begin)/CLOCKS_PER_SEC);

        // 第六步，验证方分发AES密钥给用户
        verify_distribute_aes_key(&verify, clients, client_count);

        // 第七步，发送PSI结果到验证方
        send_result_to_verify(clients, client_count, &psi_cloud, &verify, &mods);

        t_check_begin = clock();
        // 最后一步，验证方合并结果并检查交集
        verify_merge_and_check_intersection(&verify, &mods);
        
        t_check_end = clock();
        printf("检查阶段耗时：%.3f 秒\n", (double)(t_check_end - t_check_begin)/CLOCKS_PER_SEC);

        // 释放内存
        // 释放客户端
        for (size_t i = 0; i < client_count; ++i) {
            client_free(clients[i]);
            free(clients[i]);
        }

        // 释放 PSI云平台
        psi_cloud_free(&psi_cloud);

        // 释放 Beaver云平台
        beaver_cloud_free(&beaver_cloud);

        // 释放验证方
        verify_free(&verify);
    
    }

    return 0;

}