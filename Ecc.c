#include "Ecc.h"

// 点加(y^2 = x^3 + A * x + b方程定义的点加算法) 
// R(x, y) = P(x, y) + Q(x, y); // 需求解关于两点的线段关系。
// 点加顺序很重要，斜率不存在的时候默认 R = Q
void EccPointAdd(EccVar * Rx, EccVar * Ry, EccVar Px, EccVar Py, EccVar Qx, EccVar Qy, EccVar A, EccVar P)
{
	// K为P与Q两点切线方程的斜率，T为临时变量
	EccVar K = 0, T = 0;
	// Tx = (Qx - Px), 无符号运算，防止下溢出。
	EccVar Tx = CryptSafeSubMod(Qx, Px, P); // (Qx < Px) ? P + Qx - Px : Qx - Px;
	// Ty = (Qy - Py), 无符号运算，防止下溢出。
	EccVar Ty = CryptSafeSubMod(Qy, Py, P); // (Qy < Py) ? P + Qy - Py : Qy - Py;
	// Tx = (Qx - Px) != 0
	// (判断斜率 K 是否存在，线段是否垂直于X轴)
	if (0 != Tx)
	{
		// 求解乘法逆元 T = (1 / Tx) mod P
		T = CryptEgcdInverse(Tx, P);
		// 求解斜率 K = (Ty * T) mod P => K = (Ty / Tx) mod P
		K = CryptFastMulMod(Ty, T, P);
	}
	else
	{
		if (0 == Ty)
		{
			// ∵ Ty = Qy - Py => Qy == Py => (Qy + Py) == 2 * Py
			// ∴ K = (T * K) % P => K = ((3 * Px ^ 2 + A) * (1 / (2 * Py)) mod P) mod P
			// K = Ty mod P, K = (1 / K) mod P => K = (1 / (Qy + Py)) mod P
			K = CryptSafeAddMod(Py, Qy, P), K = CryptEgcdInverse(K, P);
			// T = 3 * Px ^ 2 + A
			T = CryptFastMulMod(3, CryptFastMulMod(Px, Px, P), P) + A;
			// K = (T * K) % P => K = ((3 * Px ^ 2 + A) * (1 / (2 * Py)) mod P) mod P
			K = CryptFastMulMod(T, K, P);
		}
		else
		{
			// 斜率 K 不存在，所以R(x, y) = Q(x, y)。
			*Rx = Qx, *Ry = Qy;
			return; // 终止 
		}
	}
	// T = K * K, T = T - Px, Rx = (T - Qx) % P => Rx = (K ^ 2 - Px - Qx) mod P
	T = CryptFastMulMod(K, K, P), T = CryptSafeSubMod(T, Px, P), *Rx = CryptSafeSubMod(T, Qx, P);
	// T = Px - Rx, T = T * K, Ry = (T - Py) mod P => Ry = (Px - Rx) * K - Py
	T = CryptSafeSubMod(Px, *Rx, P), T = CryptFastMulMod(T, K, P), *Ry = CryptSafeSubMod(T, Py, P);
}

// 点乘(即求点P的K倍，即K个P点加), 采用的算法为二元展开法
// K(x, y) = k * P(x, y)
void EccPointMul(EccVar * Kx, EccVar * Ky, EccVar Px, EccVar Py, EccVar K, EccVar A, EccVar P)
{
	*Kx = Px, *Ky = Py;
	K = K - 1;
	if (K > 0)
	{
		WHERE:
		if (K & 1)
		{
			EccPointAdd(Kx, Ky, Px, Py, *Kx, *Ky, A, P);
		}
		K >>= 1;
		if (0 == K)
		{
			return;
		}
		EccPointAdd(&Px, &Py, Px, Py, Px, Py, A, P);
		goto WHERE;
	}
}

void EccCryptInit(EccCrypt * Self, EccVar P, EccVar A, EccVar K)
{
	Self->A = A, Self->P = P, Self->K = K;
}

#include <math.h>

// 设置椭圆曲线和选取基点，返回椭圆曲线y^2 = (x^3 + a*x + b) mod p的b值。
void EccCryptSetEcc(EccCrypt * Self, EccEnCrypt * En, EccVar P, EccVar A, EccVar K)
{
	// 设置特征不等于2和3的光滑椭圆曲线 y^2 = (x^3 + a*x + b) mod p
	Self->A = A, Self->P = P;
	// 椭圆方程Ep(a,b)须满足代数式: △ = 4 * a^3 + 27 * b^2 ≠ 0 (mod p)
	// △ ≠ 0 确保了曲线光滑且无重根，即曲线上的点不会有重合。
	// tmpA = 4 * a^3
	EccVar tmpA = 4 * pow(A, 3), b = 0, tmpB = 0, i = 1;
	do
	{
		b = i++;
		// tmpB = 27 * b^2;
		tmpB = 27 * pow(b, 2);
		tmpB = (tmpA + tmpB) % P;
	} while (0 == tmpB);
	// 选取基点G(x, y), 随机选取 x 代入方程: y^2 = x^3 + a * x + b, 从而得到 y。
	EccVar MaxGx = pow(P, 1.0 / 3.0); // 小于根号三的最大值
	En->Gx = rand() % MaxGx; // Gx ^ 3 < p
	// tmp = Gx ^ 3, tmp = tmp + a * Gx + b, tmp = Gx ^ 3 + a * Gx + b
	EccVar tmp = pow(En->Gx, 3) + A * En->Gx + b;
	// y = sqrt(tmp) 会丢失精度，此时y并不是原曲线方程上的点，而是看作曲线离散的点。
	En->Gy = (EccVar) pow(tmp, 1.0 / 2.0) % P;
	// 设定一个私有密钥k，并生成公开密钥K(x, y) = k*G(x, y)
	Self->K = K;
	// K(x, y) = k*G(x, y)
	EccPointMul(&En->Kx, &En->Ky, En->Gx, En->Gy, K, A, P);
}

// 加密数据M(x, y)，基于代数式：M(x, y) = L(x, y) - k*R(x, y)
// 其中 L(x, y) = M(x, y) + r*K(x, y), R(x, y) = r*G(x, y), K(x, y) = k*G(x, y)
void EccEnCryptData(EccCrypt * Self, EccEnCrypt * En, EccVar Mx, EccVar My)
{
	// 产生一个随机阶数r（r < k），须大于零。
	EccVar Tx = 0, Ty = 0, r = (rand() % Self->K) + 1;
	// R(x, y) = r*G(x, y)
	EccPointMul(&En->Rx, &En->Ry, En->Gx, En->Gy, r, Self->A, Self->P);
	// T(x, y) = r*K(x, y) 注: K(x, y) = k*G(x, y)
	EccPointMul(&Tx, &Ty, En->Kx, En->Ky, r, Self->A, Self->P);
	// L(x, y) = M(x, y) + T(x, y) => L(x, y) = M(x, y) + r*K(x, y)
	EccPointAdd(&En->Lx, &En->Ly, Tx, Ty, Mx, My, Self->A, Self->P);
}

// 解密数据，基于代数式：M(x, y) = L(x, y) - k*R(x, y)
// 根据 EccEnCryptData 注释有 
// M(x, y) = L(x, y) - k*R(x, y) = M(x, y) + r*k*G(x, y) - k*r*G(x, y)
void EccDeCryptData(EccCrypt * Self, EccEnCrypt * En, EccDeCrypt * De)
{
	EccVar Tx = 0, Ty = 0;
	// T(x, y) = k*R(x, y)
	EccPointMul(&Tx, &Ty, En->Rx, En->Ry, Self->K, Self->A, Self->P);
	// T(x, y) = -T(x, y) 注:T(x, y)的负元是 -T(x, -y)
	Ty = -Ty;
	// M(x, y) = L(x, y) + T(x, y) => M(x, y) = L(x, y) - k*R(x, y)
	EccPointAdd(&De->Mx, &De->My, Tx, Ty, En->Lx, En->Ly, Self->A, Self->P);
}

#ifdef UNIT_TEST

#include <stdio.h>
#include <assert.h>

int unit_test_ecc(EccVar P)
{
	// 初始化 加密端
	EccCrypt EccEn;
	EccEnCrypt En;
	EccCryptSetEcc(&EccEn, &En, P, 1, P);

	// 初始化 解密端
	EccCrypt EccDe;
	EccDeCrypt De;
	EccCryptInit(&EccDe, P, 1, P);

	// EccVar i = 10;
	for (EccVar i = 0; i != P; i++)
	{
		EccEnCryptData(&EccEn, &En, i, i);

		// De.Mx = De.My = 0;

		EccDeCryptData(&EccDe, &En, &De);
		
		assert(De.Mx == De.My);

		printf("i:\t%02hhX\n", i);

		if (De.Mx != De.My)
		{
			printf("M(%02hhX, %02hhX)\n", De.Mx, De.My);
			// break;
		}
		else
		{
			printf("L(%02hhX, %02hhX)-R(%02hhX, %02hhX)\n", En.Lx, En.Ly, En.Rx, En.Ry);
		}
	}

	// system("pause");
	return 0;
}

#include <Windows.h>

int main()
{
	// srand(time(NULL));
	// EccVar res = EccGetPrime(UINT64_MAX); // 0x7fffffffffffffe7
	// return 0;
	EccVar start = GetTickCount64();
	unit_test_ecc(INT8_MAX);
	EccVar end = GetTickCount64();
	printf("result:%02hhu\n", (CryptUint) (end - start));
	system("pause");
	return 0;
}

#endif
