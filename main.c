
#include "PSI.h"
#include "client.h"
#include "PSI_Cloud.h"
#include "Verify.h"
#include "Beaver_Cloud.h"

// 定义数据集大小2^k
#define DATASET_NUM 10

// 定义桶数量
#define BUCKET_NUM 21

// 定义数据比特位数
#define DATA_BIT 40

int main(){

    // 用户数量
    int client_count = 3;
    
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
    modsystem_init_auto(&mods, 200, 123);

    // 初始化客户端
    for (size_t i = 0; i < client_count; ++i) {
        clients[i] = malloc(sizeof(Client));
        client_init(clients[i], DATASET_NUM, DATA_BIT, BUCKET_NUM, 123, i+1);
        client_build_buckets(clients[i]);
        client_insert_dataset(clients[i]);
    }

    // 初始化验证方
    verify_init(&verify, DATASET_NUM, DATA_BIT, BUCKET_NUM, 456);
    verify_build_buckets(&verify);
    verify_insert_dataset(&verify);

    // 初始化PSI云平台
    psi_cloud_init(&psi_cloud, client_count+1, BUCKET_NUM, DATA_BIT, 123);

    // 初始化Beaver云平台
    beaver_cloud_init(&beaver_cloud, DATA_BIT, 123);

    // 进行PSI
    // 第一步，PSI云平台将AES密钥发送给各方
    psi_sync_all_clients(&psi_cloud, clients, client_count, &verify, &beaver_cloud);

    // 第二步，用户上传桶
    Clients_send_encrypted_buckets(clients, client_count, &psi_cloud);
    
    // 第三步，验证方上传桶
    psi_send_encrypted_buckets_verify(&verify, &psi_cloud);

    // 第四步，Beaver云平台分发多项式Beaver三元组
    beaver_cloud_distribute_to_client(&beaver_cloud, clients, client_count, &psi_cloud, &verify);

    // 第五步，计算多项式Beaver三元组结果
    beaver_compute_multiplication(clients, client_count, &psi_cloud, &verify, &mods);

    // 第六步，验证方分发AES密钥给用户
    verify_distribute_aes_key(&verify, clients, client_count);

    // 第七步，发送PSI结果到验证方
    send_result_to_verify(clients, client_count, &psi_cloud, &verify, &mods);

    // 最后一步，验证方合并结果并检查交集
    verify_merge_and_check_intersection(&verify, &mods);

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

    return 0;

}