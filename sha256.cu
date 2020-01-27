#include <cstring>
#include <fstream>
#include <iostream>
#ifndef SHA256_H
#define SHA256_H
#include <string>

class SHA256
{
protected:

    const static unsigned int sha256_k[];
    static const unsigned int SHA224_256_BLOCK_SIZE = (512/8);
public:
    void init();
    void update(const unsigned char *message, unsigned int len);
    void final(unsigned char *digest);
    static const unsigned int DIGEST_SIZE = ( 256 / 8);

protected:
    void transform(const unsigned char *message, unsigned int block_nb, unsigned int number_of_elements);
    unsigned int m_tot_len;
    unsigned int m_len;
    unsigned char m_block[2*SHA224_256_BLOCK_SIZE];
    unsigned int m_h[8];
};

std::string sha256(std::string input);

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                         \
{                                                     \
    *((str) + 3) = (unsigned char) ((x)      );       \
    *((str) + 2) = (unsigned char) ((x) >>  8);       \
    *((str) + 1) = (unsigned char) ((x) >> 16);       \
    *((str) + 0) = (unsigned char) ((x) >> 24);       \
}
#define SHA2_PACK32(str, x)                           \
{                                                     \
    *(x) =   ((unsigned int) *((str) + 3)      )      \
           | ((unsigned int) *((str) + 2) <<  8)      \
           | ((unsigned int) *((str) + 1) << 16)      \
           | ((unsigned int) *((str) + 0) << 24);     \
}
#endif

using std::string;
using std::cout;
using std::endl;


const unsigned int SHA256::sha256_k[64] = //UL = uint32
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__device__ unsigned int t11;
__device__ unsigned int t12;

__global__ void kernel1(unsigned char* sub_block_d, unsigned int *w_d, unsigned int *wv, unsigned int *m_h) {

    int j = threadIdx.x;

    wv[j] = m_h[j];

    if ( j >= 8 ) {
        SHA2_PACK32(&sub_block_d[j << 2], &w_d[j]);
        // printf("%d %d\n", sub_block_d[j << 2], w_d[j]);
    }
}

__global__ void kernel2(unsigned int *w_d, unsigned int *wv, unsigned int *sha256_k) {

    int j = threadIdx.x;
    if (j >= 16){
        w_d[j] = SHA256_F4(w_d[j -  2]) + w_d[j -  7] + SHA256_F3(w_d[j - 15]) + w_d[j - 16];
    }

    t11 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
    + sha256_k[j] + w_d[j];
    t12 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
    wv[7] = wv[6];
    wv[6] = wv[5];
    wv[5] = wv[4];
    wv[4] = wv[3] + t11;
    wv[3] = wv[2];
    wv[2] = wv[1];
    wv[1] = wv[0];
    wv[0] = t11 + t12;

}

__global__ void kernel3(unsigned int *wv, unsigned int *m_h) {

    int j = threadIdx.x;    
    m_h[j] += wv[j];

}

void SHA256::transform(const unsigned char *message, unsigned int block_nb, unsigned int number_of_elements)
{
    unsigned int w[64];
    unsigned int wv[8];
    unsigned int *wv1;
    unsigned int *w_d;
    unsigned int *sha256_k1;

    unsigned int *wv_d;
    unsigned int *m_h_d;

    const unsigned char *sub_block;
    unsigned char *sub_block_d;
    int i;
    for (i = 0; i < (int) block_nb; i++) {

        sub_block = message + (i << 6);

        ///////////////////////// K 1 ////////////////////////////////
        cudaMalloc((void **) &sub_block_d, sizeof(unsigned char) * number_of_elements);
        cudaMemcpy(sub_block_d, sub_block, sizeof(unsigned char) * number_of_elements, cudaMemcpyHostToDevice);

        cudaMalloc((void **) &w_d, sizeof(unsigned int) * 64);
        cudaMemcpy(w_d, w, sizeof(unsigned int) * 64, cudaMemcpyHostToDevice);

        cudaMalloc((void **) &wv_d, sizeof(unsigned int) * 8);
        cudaMemcpy(wv_d, wv, sizeof(unsigned int) * 8, cudaMemcpyHostToDevice);

        cudaMalloc((void **) &m_h_d, sizeof(unsigned int) * 8);
        cudaMemcpy(m_h_d, m_h, sizeof(unsigned int) * 8, cudaMemcpyHostToDevice);

        kernel1<<<1, 16>>>(sub_block_d, w_d, wv_d, m_h_d);

        cudaDeviceSynchronize();
        cudaMemcpy(w, w_d, sizeof(unsigned int) * 64, cudaMemcpyDeviceToHost);
        cudaMemcpy(wv, wv_d, sizeof(unsigned int) * 8, cudaMemcpyDeviceToHost);
        cudaMemcpy(m_h, m_h_d, sizeof(unsigned int) * 8, cudaMemcpyDeviceToHost);
        // for(int k = 0; k < 64; k++){
        //     printf("%d ", w[k]);
        // }

        //////////////////////// K 2 ////////////////////////////////
        cudaMemcpy(w_d, w, sizeof(unsigned int) * 64, cudaMemcpyHostToDevice);

        cudaMalloc((void **) &wv1, sizeof(unsigned int) * 8);
        cudaMemcpy(wv1, wv, sizeof(unsigned int) * 8, cudaMemcpyHostToDevice);

        cudaMalloc((void **) &sha256_k1, sizeof(unsigned int) * 64);
        cudaMemcpy(sha256_k1, sha256_k, sizeof(unsigned int) * 64, cudaMemcpyHostToDevice);

        kernel2<<<1, 64>>>(w_d, wv1, sha256_k1);

        cudaDeviceSynchronize();
        cudaMemcpy(wv, wv1, sizeof(unsigned int) * 8, cudaMemcpyDeviceToHost);
        cudaMemcpy(w, w_d, sizeof(unsigned int) * 64, cudaMemcpyDeviceToHost);
       
        //////////////////////////K 3///////////////////////////////
        cudaMemcpy(wv1, wv, sizeof(unsigned int) * 8, cudaMemcpyHostToDevice);
        cudaMemcpy(m_h_d, m_h, sizeof(unsigned int) * 8, cudaMemcpyHostToDevice);

        kernel3<<<1, 8>>>(wv1, m_h_d);

        cudaDeviceSynchronize();
        cudaMemcpy(wv, wv1, sizeof(unsigned int) * 8, cudaMemcpyDeviceToHost);
        cudaMemcpy(m_h, m_h_d, sizeof(unsigned int) * 8, cudaMemcpyDeviceToHost);
    }
}

void SHA256::init()
{
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    transform(m_block, 1, SHA224_256_BLOCK_SIZE);
    transform(shifted_message, block_nb, SHA224_256_BLOCK_SIZE);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb, block_nb * len_b);
    for (i = 0 ; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}

std::string sha256(std::string input)
{
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest,0,SHA256::DIGEST_SIZE);

    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update( (unsigned char*)input.c_str(), input.length());
    ctx.final(digest);

    char buf[2*SHA256::DIGEST_SIZE+1];
    buf[2*SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf+i*2, "%02x", digest[i]);
    return std::string(buf);
}
int main(int argc, char *argv[])
{
    string input = "apple";
    string output1 = sha256(input);

    cout << "sha256('"<< input << "'):" << output1 << endl;
    return 0;
}