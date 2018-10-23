#include "../Crypt.h"

typedef CryptInt EccVar;

// 点加(y^2 = x^3 + A * x + b方程定义的点加算法) 
// R(x, y) = P(x, y) + Q(x, y); // 需求解关于两点的线段关系。
// 点加顺序很重要，斜率不存在的时候默认 R = Q
void EccPointAdd(EccVar * Rx, EccVar * Ry, EccVar Px, EccVar Py, EccVar Qx, EccVar Qy, EccVar A, EccVar P);

// 点乘(即求点P的K倍，即K个P点加), 采用的算法为二元展开法
// K(x, y) = k * P(x, y)
void EccPointMul(EccVar * Kx, EccVar * Ky, EccVar Px, EccVar Py, EccVar K, EccVar A, EccVar P);

typedef struct elliptic_curve_cryptography_crypt
{
	EccVar P, A, K;
}EccCrypt;

void EccCryptInit(EccCrypt * Self, EccVar P, EccVar A, EccVar K);

typedef struct elliptic_curve_cryptography_encrypt
{
	EccVar Gx, Gy, Kx, Ky;
	EccVar Rx, Ry, Lx, Ly;
}EccEnCrypt;

// 设置椭圆曲线和选取基点，返回椭圆曲线y^2 = (x^3 + a*x + b) mod p的b值。
void EccCryptSetEcc(EccCrypt * Self, EccEnCrypt * En, EccVar P, EccVar A, EccVar K);

// 加密数据M(x, y)，基于代数式：M(x, y) = L(x, y) - k*R(x, y)
// 其中 L(x, y) = M(x, y) + r*K(x, y), R(x, y) = r*G(x, y), K(x, y) = k*G(x, y)
void EccEnCryptData(EccCrypt * Self, EccEnCrypt * En, EccVar Mx, EccVar My);

typedef struct elliptic_curve_cryptography_decrypt
{
	EccVar Mx, My;
}EccDeCrypt;

// 解密数据，基于代数式：M(x, y) = L(x, y) - k*R(x, y)
// 根据 EccEnCryptData 注释有 
// M(x, y) = L(x, y) - k*R(x, y) = M(x, y) + r*k*G(x, y) - k*r*G(x, y)
void EccDeCryptData(EccCrypt * Self, EccEnCrypt * En, EccDeCrypt * De);
