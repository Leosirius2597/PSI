#include "bucket.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>


// -----------------------------
// 初始化空桶集合（不生成随机根）
// -----------------------------
void bucket_init(BucketSet *set, unsigned int n, unsigned int m_bit) {
    if (!set || n == 0 || m_bit == 0) {
        fprintf(stderr, "bucket_init: invalid parameters\n");
        exit(EXIT_FAILURE);
    }

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = malloc(sizeof(Bucket) * n);
    if (!set->buckets) {
        fprintf(stderr, "bucket_init: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < n; ++i) {
        Bucket *b = &set->buckets[i];

        // 初始化多项式根与系数
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            mpz_init(b->roots[j]);
            mpz_set_ui(b->roots[j], 0);
        }
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
            mpz_init(b->coeffs[j]);
            mpz_set_ui(b->coeffs[j], 0);
        }

        // 初始化随机标识和元素计数
        mpz_init(b->tag);
        mpz_set_ui(b->tag, 0);
        b->element_num = 0;
    }
}

// -----------------------------
// 初始化结果桶集合（不生成随机根）
// -----------------------------
void result_bucket_init(Result_BucketSet *result_set, unsigned int n){
    if (!result_set || n == 0) {
        fprintf(stderr, "result_bucket_init: invalid parameters\n");
        exit(EXIT_FAILURE);
    }
    
    result_set-> count = n;
    result_set->result_buckets = malloc(sizeof(Result_Bucket) * n);
    if (!result_set->result_buckets) {
        fprintf(stderr, "result_bucket_init: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    
    for (size_t i = 0; i < n; ++i) {
        Result_Bucket *b = &result_set->result_buckets[i];

        // 初始化结果多项式系数
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
            mpz_init(b->coeffs[j]);
            mpz_set_ui(b->coeffs[j], 0);
        }

        // 初始化随机标识
        mpz_init(b->tag);
        mpz_set_ui(b->tag, 0);
    }  
}

// -----------------------------
// 初始化桶集合（生成随机根）
// -----------------------------
void bucket_generate(BucketSet *set, unsigned int n, unsigned int m_bit, unsigned long seed) {
    if (!set || n == 0 || m_bit == 0) {
        fprintf(stderr, "bucket_generate: invalid parameters\n");
        exit(EXIT_FAILURE);
    }

    if (seed == 0)
        seed = (unsigned long)time(NULL);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, seed);

    set->count = n;
    set->m_bit = m_bit;
    set->buckets = malloc(sizeof(Bucket) * n);
    if (!set->buckets) {
        fprintf(stderr, "bucket_generate: memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    mpz_t temp;
    mpz_init(temp);

    for (size_t i = 0; i < n; ++i) {
        // 初始化桶随机标识
        mpz_init(set->buckets[i].tag);
        // 初始化根与系数
        for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
            mpz_init(set->buckets[i].roots[j]);
            mpz_urandomb(temp, state, m_bit);
            mpz_set(set->buckets[i].roots[j], temp);
        }
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j)
            mpz_init(set->buckets[i].coeffs[j]);
    }

    mpz_clear(temp);
    gmp_randclear(state);
}


void bucket_expand(BucketSet *set) {
    if (!set || !set->buckets) return;

    mpz_t tmp;
    mpz_init(tmp);

    for (size_t i = 0; i < set->count; ++i) {
        Bucket *b = &set->buckets[i];

        // 初始化：P(x) = 1
        for (size_t k = 0; k < BUCKET_POLY_LEN; ++k)
            mpz_set_ui(b->coeffs[k], 0);
        mpz_set_ui(b->coeffs[0], 1); // 最高次项系数

        // 对每个根 r_i 执行 P(x) *= (x - r_i)
        for (size_t r = 0; r < BUCKET_ROOTS; ++r) {
            // 从高次往低次更新系数（降幂形式）
            for (ssize_t k = r + 1; k >= 1; --k) {
                // coeff[k] = coeff[k] - r_i * coeff[k-1]
                mpz_mul(tmp, b->coeffs[k - 1], b->roots[r]);
                mpz_sub(b->coeffs[k], b->coeffs[k], tmp);
            }
        }
    }

    mpz_clear(tmp);
}


void bucket_print(const BucketSet *set, size_t bucket_count, size_t roots_per_bucket) {
    if (!set || !set->buckets) return;
    if (bucket_count > set->count) bucket_count = set->count;
    if (roots_per_bucket > BUCKET_ROOTS) roots_per_bucket = BUCKET_ROOTS;

    for (size_t i = 0; i < bucket_count; ++i) {
        printf("Bucket[%zu] roots:\n", i);
        for (size_t j = 0; j < roots_per_bucket; ++j)
            gmp_printf("  r[%03zu] = %Zd\n", j, set->buckets[i].roots[j]);
        printf("\n");
    }
}

void bucket_print_poly(const BucketSet *set, size_t bucket_count, size_t coeffs_to_show) {
    if (!set || !set->buckets) return;
    if (bucket_count > set->count) bucket_count = set->count;
    if (coeffs_to_show > BUCKET_POLY_LEN) coeffs_to_show = BUCKET_POLY_LEN;

    for (size_t i = 0; i < bucket_count; ++i) {
        printf("Bucket[%zu] polynomial coefficients:\n", i);
        for (size_t j = 0; j < coeffs_to_show; ++j)
            gmp_printf("  a[%03zu] = %Zd\n", j, set->buckets[i].coeffs[j]);
        printf("\n");
    }
}

void bucket_free(BucketSet *set) {
    if (!set || !set->buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        for (size_t j = 0; j < BUCKET_ROOTS; ++j)
            mpz_clear(set->buckets[i].roots[j]);
        for (size_t j = 0; j < BUCKET_POLY_LEN; ++j)
            mpz_clear(set->buckets[i].coeffs[j]);
        mpz_clear(set->buckets[i].tag); 
    }

    free(set->buckets);
    set->buckets = NULL;
    set->count = 0;
}

void result_bucket_free(Result_BucketSet *set) {
    if (!set || !set->result_buckets) return;

    for (size_t i = 0; i < set->count; ++i) {
        for (size_t j = 0; j < RESULT_POLY_LEN; ++j)
            mpz_clear(set->result_buckets[i].coeffs[j]);
        mpz_clear(set->result_buckets[i].tag);
    }

    free(set->result_buckets);
    set->result_buckets = NULL;
    set->count = 0;
}


// -----------------------------
// 桶内根替换操作
// -----------------------------
//
// 参数:
//   poly   : 多项式系数（长度 degree+1）
//   degree : 多项式次数（例如桶长度-1）
//   r_out  : 被替换出去的根
//   r_in   : 要替换进来的新根
//
// 过程:
//   1. Q(x) = P(x) / (x - r_out)
//   2. P'(x) = Q(x) * (x - r_in)
// -----------------------------
// 合成除法（降幂）：Q(x) = P(x) / (x - r_out)
// 输入：a[0..d] 为降幂系数（a[0] 最高次，a[d] 常数项）
// 输出：q[0..d-1]（降幂），返回余数 rem = P(r_out)
static void synthetic_division_desc(const mpz_t *a, size_t d,
                                    const mpz_t r_out,
                                    mpz_t *q, mpz_t rem)
{
    // q[0] = a[0]
    mpz_set(q[0], a[0]);

    // 对 i = 1..d-1: q[i] = a[i] + r_out * q[i-1]
    mpz_t t;
    mpz_init(t);
    for (size_t i = 1; i <= d - 1; ++i) {
        mpz_mul(t, r_out, q[i - 1]);
        mpz_add(q[i], a[i], t);
    }
    // remainder = a[d] + r_out * q[d-1]
    mpz_mul(t, r_out, q[d - 1]);
    mpz_add(rem, a[d], t);
    mpz_clear(t);
}

// 乘回 (x - r_in)：P'(x) = Q(x) * (x - r_in)
// q: 长度 d（降幂，度 d-1）；输出 new_a: 长度 d+1（降幂，度 d）
static void multiply_by_monic_linear_desc(const mpz_t *q, size_t d,
                                          const mpz_t r_in,
                                          mpz_t *new_a)
{
    // new_a[0] = q[0]
    mpz_set(new_a[0], q[0]);

    // new_a[i] = q[i] - r_in * q[i-1],  i = 1..d-1
    mpz_t t;
    mpz_init(t);
    for (size_t i = 1; i <= d - 1; ++i) {
        mpz_mul(t, r_in, q[i - 1]);
        mpz_sub(new_a[i], q[i], t);
    }
    // new_a[d] = - r_in * q[d-1]
    mpz_mul(t, r_in, q[d - 1]);
    mpz_neg(new_a[d], t);
    mpz_clear(t);
}

// 在多项式中替换一个根：r_out → r_in（就地更新 poly）
// poly: 降幂系数数组 a[0..degree]，a[0] 为最高次（通常为 1）
// 实现：P' = (P / (x - r_out)) * (x - r_in)
void bucket_replace_root(mpz_t *poly, size_t degree,
                         const mpz_t r_out, const mpz_t r_in)
{
    if (!poly || degree == 0) return;

    mpz_t *q = malloc(sizeof(mpz_t) * degree);
    mpz_t *new_coeffs = malloc(sizeof(mpz_t) * (degree + 1));
    if (!q || !new_coeffs) {
        fprintf(stderr, "bucket_replace_root: malloc failed\n");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < degree; ++i) mpz_init(q[i]);
    for (size_t i = 0; i <= degree; ++i) mpz_init(new_coeffs[i]);

    mpz_t rem;
    mpz_init(rem);

    synthetic_division_desc((const mpz_t*)poly, degree, r_out, q, rem);
    if (mpz_sgn(rem) != 0)
        gmp_printf("[警告] 替换时余数 ≠ 0 (rem=%Zd)\n", rem);

    multiply_by_monic_linear_desc((const mpz_t*)q, degree, r_in, new_coeffs);

    for (size_t i = 0; i <= degree; ++i)
        mpz_set(poly[i], new_coeffs[i]);

    // 清理
    for (size_t i = 0; i < degree; ++i) mpz_clear(q[i]);
    for (size_t i = 0; i <= degree; ++i) mpz_clear(new_coeffs[i]);
    mpz_clear(rem);
    free(q);
    free(new_coeffs);
}

// -----------------------------
// 桶拷贝函数：深拷贝 roots、coeffs、tag
// -----------------------------
void bucket_copy(Bucket *dest, const Bucket *src) {
    if (!dest || !src) return;

    // 拷贝 roots
    for (size_t j = 0; j < BUCKET_ROOTS; ++j) {
        mpz_init(dest->roots[j]);
        mpz_set(dest->roots[j], src->roots[j]);
    }

    // 拷贝 coeffs
    for (size_t j = 0; j < BUCKET_POLY_LEN; ++j) {
        mpz_init(dest->coeffs[j]);
        mpz_set(dest->coeffs[j], src->coeffs[j]);
    }

    // 拷贝 tag
    mpz_init(dest->tag);
    mpz_set(dest->tag, src->tag);

    // 复制其他属性
    dest->element_num = src->element_num;
}

// -----------------------------
// 结果桶拷贝函数：深拷贝 coeffs、tag
// -----------------------------
void result_bucket_copy(Result_Bucket *dest, const Result_Bucket *src) {
    if (!dest || !src) return;

    for (size_t j = 0; j < RESULT_POLY_LEN; ++j) {
        mpz_init(dest->coeffs[j]);
        mpz_set(dest->coeffs[j], src->coeffs[j]);
    }

    mpz_init(dest->tag);
    mpz_set(dest->tag, src->tag);
}


