/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <cooky451> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 * You can reach me at irc.euirc.org. #c++, #prettyos, #rhr
 * Also known as captain-cooky since my IRC client just loves to change my 
 * name.
 * ----------------------------------------------------------------------------
 */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>
#include <limits>
#include <exception>
#include <stdexcept>

#include "sha2.hpp"

#define SHA2_HASH_USE_EXCEPTIONS_FOR_OVERFLOW // Static If I Had a Hammer ;)
#define SHA2_CARE_ABOUT_INTEGER_OVERFLOW

namespace 
{
	using namespace sha2;
	using namespace detail;

	// 4.2.2 SHA-224 and SHA-256 Constants
	const word32 K32[64] = 
	{
		0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul, 0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul, 
		0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul, 0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul, 
		0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul, 0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul, 
		0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul, 0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul, 
		0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul, 0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul, 
		0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul, 0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul, 
		0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul, 0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul, 
		0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul, 0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul, 
	};

	// 4.2.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constants
	const word64 K64[80] = 
	{
		0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 
		0x3956c25bf348b538ull, 0x59f111f1b605d019ull, 0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 
		0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull, 
		0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull, 
		0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull, 0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 
		0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull, 
		0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 
		0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull, 0x06ca6351e003826full, 0x142929670a0e6e70ull, 
		0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull, 
		0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull, 
		0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull, 0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 
		0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull, 
		0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 
		0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull, 0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 
		0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull, 
		0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 
		0xca273eceea26619cull, 0xd186b8c721c0c207ull, 0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 
		0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull, 
		0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull, 
		0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull, 0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull, 
	};

	word32 swap_bytes(word32 w)
	{
		return 
				((((w) & 0xFF000000ul) >> 24) 
			| (((w) & 0x00FF0000ul) >> 8) 
			| (((w) & 0x0000FF00ul) << 8) 
			| (((w) & 0x000000FFul) << 24));
	}

	word64 swap_bytes(word64 w)
	{
		return 
				((((w) & 0xFF00000000000000ull) >> 56) 
			| (((w) & 0x00FF000000000000ull) >> 40) 
			| (((w) & 0x0000FF0000000000ull) >> 24) 
			| (((w) & 0x000000FF00000000ull) >> 8)
			| (((w) & 0x00000000FF000000ull) << 8) 
			| (((w) & 0x0000000000FF0000ull) << 24) 
			| (((w) & 0x000000000000FF00ull) << 40) 
			| (((w) & 0x00000000000000FFull) << 56));
	}

	// 5.3.2 SHA-224
	const array<word32, 8> sha224_H0 = 
	{{ // GCC complains about missing braces without this.
		0xc1059ed8ul, 0x367cd507ul, 0x3070dd17ul, 0xf70e5939ul, 
		0xffc00b31ul, 0x68581511ul, 0x64f98fa7ul, 0xbefa4fa4ul, 
	}};

	// 5.3.3 SHA-256
	const array<word32, 8> sha256_H0 = 
	{{
		0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul, 
		0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul, 
	}};

	// 5.3.4 SHA-384
	const array<word64, 8> sha384_H0 = 
	{{
		0xcbbb9d5dc1059ed8ull, 0x629a292a367cd507ull, 0x9159015a3070dd17ull, 0x152fecd8f70e5939ull, 
		0x67332667ffc00b31ull, 0x8eb44a8768581511ull, 0xdb0c2e0d64f98fa7ull, 0x47b5481dbefa4fa4ull, 
	}};

	// 5.3.5 SHA-512
	const array<word64, 8> sha512_H0 = 
	{{
		0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull, 
		0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull, 
	}};

	// 5.3.6.1 SHA-512/224
	const array<word64, 8> sha512_224_H0 = 
	{{
		0x8C3D37C819544DA2ull, 0x73E1996689DCD4D6ull, 0x1DFAB7AE32FF9C82ull, 0x679DD514582F9FCFull, 
		0x0F6D2B697BD44DA8ull, 0x77E36F7304C48942ull, 0x3F9D85A86A1D36C8ull, 0x1112E6AD91D692A1ull, 
	}};

	// 5.3.6.2 SHA-512/256
	const array<word64, 8> sha512_256_H0 = 
	{{
		0x22312194FC2BF72Cull, 0x9F555FA3C84C64C2ull, 0x2393B86B6F53B151ull, 0x963877195940EABDull, 
		0x96283EE2A88EFFE3ull, 0xBE5E1E2553863992ull, 0x2B0199FC2C85B8AAull, 0x0EB72DDC81C52CA2ull, 
	}};

	// 2.2.2 Symbols and Operations
	template <unsigned N, typename Word>
	Word shl(Word w)
	{
		return w << (N);
	}

	template <unsigned N, typename Word>
	Word shr(Word w)
	{
		return w >> (N);
	}

	template <unsigned N, typename Word>
	Word rotr(Word w)
	{
		return shr<N>(w) | shl<sizeof(Word) * 8 - N>(w);
	}

	// 4.1.2 SHA-224 and SHA-256 Functions
	// 4.1.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions
	template <typename Word>
	Word ch(Word x, Word y, Word z)
	{
		// return (x & y) ^ (~x & z);
		// return ((y ^ z) & x) ^ z;
		return z ^ (x & (y ^ z));
	}

	template <typename Word>
	Word maj(Word x, Word y, Word z)
	{
		// return (x & y) ^ (x & z) ^ (y & z);
		// return (y & z) | ((y | z) & x);
		return y ^ ((x ^ y) & (y ^ z));
	}

	// 4.1.2 SHA-224 and SHA-256 Functions
	word32 S0(word32 x)
	{
		return rotr<2>(x) ^ rotr<13>(x) ^ rotr<22>(x);
	}

	word32 S1(word32 x)
	{
		return rotr<6>(x) ^ rotr<11>(x) ^ rotr<25>(x);
	}

	word32 s0(word32 x)
	{
		return rotr<7>(x) ^ rotr<18>(x) ^ shr<3>(x);
	}

	word32 s1(word32 x)
	{
		return rotr<17>(x) ^ rotr<19>(x) ^ shr<10>(x);
	}

	// 4.1.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions
	word64 S0(word64 x)
	{
		return rotr<28>(x) ^ rotr<34>(x) ^ rotr<39>(x);
	}

	word64 S1(word64 x)
	{
		return rotr<14>(x) ^ rotr<18>(x) ^ rotr<41>(x);
	}

	word64 s0(word64 x)
	{
		return rotr<1>(x) ^ rotr<8>(x) ^ shr<7>(x);
	}

	word64 s1(word64 x)
	{
		return rotr<19>(x) ^ rotr<61>(x) ^ shr<6>(x);
	}

	template <typename Word>
	void round(Word a, Word b, Word c, Word& d, Word e, Word f, Word g, Word& h, Word kw)
	{
		Word t1 = h + S1(e) + ch(e, f, g) + kw;
		d += t1;
		h = t1 + S0(a) + maj(a, b, c);
	}

	template <size_t Rounds, typename Word, typename Constants>
	void sha2_transform(array<Word, 8>& H, const array<Word, 16>& M, Constants K)
	{
		static_assert(Rounds >= 16 && Rounds % 16 == 0, "Rounds must be divisible by 16.");

		array<Word, Rounds> W;

		W[0] = swap_bytes(M[0]);
		W[1] = swap_bytes(M[1]);
		W[2] = swap_bytes(M[2]);
		W[3] = swap_bytes(M[3]);
		W[4] = swap_bytes(M[4]);
		W[5] = swap_bytes(M[5]);
		W[6] = swap_bytes(M[6]);
		W[7] = swap_bytes(M[7]);
		W[8] = swap_bytes(M[8]);
		W[9] = swap_bytes(M[9]);
		W[10] = swap_bytes(M[10]);
		W[11] = swap_bytes(M[11]);
		W[12] = swap_bytes(M[12]);
		W[13] = swap_bytes(M[13]);
		W[14] = swap_bytes(M[14]);
		W[15] = swap_bytes(M[15]);

		Word a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

		round(a, b, c, d, e, f, g, h, K[0] + W[0]);
		round(h, a, b, c, d, e, f, g, K[1] + W[1]);
		round(g, h, a, b, c, d, e, f, K[2] + W[2]);
		round(f, g, h, a, b, c, d, e, K[3] + W[3]);
		round(e, f, g, h, a, b, c, d, K[4] + W[4]);
		round(d, e, f, g, h, a, b, c, K[5] + W[5]);
		round(c, d, e, f, g, h, a, b, K[6] + W[6]);
		round(b, c, d, e, f, g, h, a, K[7] + W[7]);

		round(a, b, c, d, e, f, g, h, K[8] + W[8]);
		round(h, a, b, c, d, e, f, g, K[9] + W[9]);
		round(g, h, a, b, c, d, e, f, K[10] + W[10]);
		round(f, g, h, a, b, c, d, e, K[11] + W[11]);
		round(e, f, g, h, a, b, c, d, K[12] + W[12]);
		round(d, e, f, g, h, a, b, c, K[13] + W[13]);
		round(c, d, e, f, g, h, a, b, K[14] + W[14]);
		round(b, c, d, e, f, g, h, a, K[15] + W[15]);

		const size_t step = (sizeof(void*) >= 8 && sizeof(Word) >= 8) ? 16 : 8;

		for (size_t t = 16; t != Rounds; t += step)
		{
			W[t + 0] = s1(W[t + 0 - 2]) + W[t + 0 - 7] + s0(W[t + 0 - 15]) + W[t + 0 - 16];
			round(a, b, c, d, e, f, g, h, K[t + 0] + W[t + 0]);
			W[t + 1] = s1(W[t + 1 - 2]) + W[t + 1 - 7] + s0(W[t + 1 - 15]) + W[t + 1 - 16];
			round(h, a, b, c, d, e, f, g, K[t + 1] + W[t + 1]);
			W[t + 2] = s1(W[t + 2 - 2]) + W[t + 2 - 7] + s0(W[t + 2 - 15]) + W[t + 2 - 16];
			round(g, h, a, b, c, d, e, f, K[t + 2] + W[t + 2]);
			W[t + 3] = s1(W[t + 3 - 2]) + W[t + 3 - 7] + s0(W[t + 3 - 15]) + W[t + 3 - 16];
			round(f, g, h, a, b, c, d, e, K[t + 3] + W[t + 3]);
			W[t + 4] = s1(W[t + 4 - 2]) + W[t + 4 - 7] + s0(W[t + 4 - 15]) + W[t + 4 - 16];
			round(e, f, g, h, a, b, c, d, K[t + 4] + W[t + 4]);
			W[t + 5] = s1(W[t + 5 - 2]) + W[t + 5 - 7] + s0(W[t + 5 - 15]) + W[t + 5 - 16];
			round(d, e, f, g, h, a, b, c, K[t + 5] + W[t + 5]);
			W[t + 6] = s1(W[t + 6 - 2]) + W[t + 6 - 7] + s0(W[t + 6 - 15]) + W[t + 6 - 16];
			round(c, d, e, f, g, h, a, b, K[t + 6] + W[t + 6]);
			W[t + 7] = s1(W[t + 7 - 2]) + W[t + 7 - 7] + s0(W[t + 7 - 15]) + W[t + 7 - 16];
			round(b, c, d, e, f, g, h, a, K[t + 7] + W[t + 7]);

			if (step == 16)
			{
				W[t + 8] = s1(W[t + 8 - 2]) + W[t + 8 - 7] + s0(W[t + 8 - 15]) + W[t + 8 - 16];
				round(a, b, c, d, e, f, g, h, K[t + 8] + W[t + 8]);
				W[t + 9] = s1(W[t + 9 - 2]) + W[t + 9 - 7] + s0(W[t + 9 - 15]) + W[t + 9 - 16];
				round(h, a, b, c, d, e, f, g, K[t + 9] + W[t + 9]);
				W[t + 10] = s1(W[t + 10 - 2]) + W[t + 10 - 7] + s0(W[t + 10 - 15]) + W[t + 10 - 16];
				round(g, h, a, b, c, d, e, f, K[t + 10] + W[t + 10]);
				W[t + 11] = s1(W[t + 11 - 2]) + W[t + 11 - 7] + s0(W[t + 11 - 15]) + W[t + 11 - 16];
				round(f, g, h, a, b, c, d, e, K[t + 11] + W[t + 11]);
				W[t + 12] = s1(W[t + 12 - 2]) + W[t + 12 - 7] + s0(W[t + 12 - 15]) + W[t + 12 - 16];
				round(e, f, g, h, a, b, c, d, K[t + 12] + W[t + 12]);
				W[t + 13] = s1(W[t + 13 - 2]) + W[t + 13 - 7] + s0(W[t + 13 - 15]) + W[t + 13 - 16];
				round(d, e, f, g, h, a, b, c, K[t + 13] + W[t + 13]);
				W[t + 14] = s1(W[t + 14 - 2]) + W[t + 14 - 7] + s0(W[t + 14 - 15]) + W[t + 14 - 16];
				round(c, d, e, f, g, h, a, b, K[t + 14] + W[t + 14]);
				W[t + 15] = s1(W[t + 15 - 2]) + W[t + 15 - 7] + s0(W[t + 15 - 15]) + W[t + 15 - 16];
				round(b, c, d, e, f, g, h, a, K[t + 15] + W[t + 15]);
			}
		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}

	template <typename Word>
	void sha2_finish_impl(array<Word, 8>& H, const void* data, size_t size, msize_type message_size)
	{
		array<Word, 16> M;

		message_size = swap_bytes(safe_add(message_size, size) * 8);

		auto msize = size / bytesize(M);
		auto rsize = size % bytesize(M);

		while (msize-- != 0)
		{
			std::memcpy(&M[0], data, bytesize(M));
			sha2_update(H, M);
			data = static_cast<const byte*>(data) + bytesize(M);
		}

		auto mbyte_ptr = reinterpret_cast<byte*>(&M[0]);

		std::memcpy(&M[0], data, rsize);

		*(mbyte_ptr + rsize) = 1 << 7;
		std::memset(mbyte_ptr + rsize + 1, 0, bytesize(M) - rsize - 1);

		static_assert(sizeof(Word) * 2 >= sizeof message_size, "msize_type too wide.");

		if (bytesize(M) - rsize - 1 < sizeof(Word) * 2)
		{
			sha2_update(H, M);
			std::memset(&M[0], 0, bytesize(M));
			mbyte_ptr = reinterpret_cast<byte*>(&M[0]);
		}

		std::memcpy(mbyte_ptr + bytesize(M) - sizeof message_size, &message_size, sizeof message_size);

		sha2_update(H, M);

		for (auto& w : H)
			w = swap_bytes(w);
	}

	template <typename Word, size_t DigestBits>
	void sha2_impl(void* buf, size_t buf_size, const void* data, size_t size)
	{
		auto H = H0<Word, DigestBits>();
		sha2_finish_impl(H, data, size, 0);
		std::memcpy(buf, &H[0], std::min(bytesize(H), buf_size));
	}

	template <typename Word, size_t DigestBits>
	array<byte, DigestBits / 8> sha2_impl(const void* data, size_t size)
	{
		array<byte, DigestBits / 8> hash;
		sha2_impl<Word, DigestBits>(&hash[0], bytesize(hash), data, size);
		return hash;
	}	
}

namespace sha2
{
	void sha224(void* buf, size_t buf_size, const void* data, size_t size)
	{
		sha2_impl<word32, 224>(buf, buf_size, data, size);
	}

	void sha256(void* buf, size_t buf_size, const void* data, size_t size)
	{
		sha2_impl<word32, 256>(buf, buf_size, data, size);
	}

	void sha384(void* buf, size_t buf_size, const void* data, size_t size)
	{
		sha2_impl<word64, 384>(buf, buf_size, data, size);
	}

	void sha512(void* buf, size_t buf_size, const void* data, size_t size)
	{
		sha2_impl<word64, 512>(buf, buf_size, data, size);
	}

	void sha512_224(void* buf, size_t buf_size, const void* data, size_t size)
	{
		sha2_impl<word64, 224>(buf, buf_size, data, size);
	}

	void sha512_256(void* buf, size_t buf_size, const void* data, size_t size)
	{
		sha2_impl<word64, 256>(buf, buf_size, data, size);
	}

	array<byte, 224 / 8> sha224(const void* data, size_t size)
	{
		return sha2_impl<word32, 224>(data, size);
	}

	array<byte, 256 / 8> sha256(const void* data, size_t size)
	{
		return sha2_impl<word32, 256>(data, size);
	}

	array<byte, 384 / 8> sha384(const void* data, size_t size)
	{
		return sha2_impl<word64, 384>(data, size);
	}

	array<byte, 512 / 8> sha512(const void* data, size_t size)
	{
		return sha2_impl<word64, 512>(data, size);
	}

	array<byte, 224 / 8> sha512_224(const void* data, size_t size)
	{
		return sha2_impl<word64, 224>(data, size);
	}

	array<byte, 256 / 8> sha512_256(const void* data, size_t size)
	{
		return sha2_impl<word64, 256>(data, size);
	}

	namespace detail
	{
		template <>
		const array<word32, 8>& H0<word32, 224>()
		{
			return sha224_H0;
		}

		template <>
		const array<word32, 8>& H0<word32, 256>()
		{
			return sha256_H0;
		}

		template <>
		const array<word64, 8>& H0<word64, 384>()
		{
			return sha384_H0;
		}

		template <>
		const array<word64, 8>& H0<word64, 512>()
		{
			return sha512_H0;
		}

		template <>
		const array<word64, 8>& H0<word64, 224>()
		{
			return sha512_224_H0;
		}

		template <>
		const array<word64, 8>& H0<word64, 256>()
		{
			return sha512_256_H0;
		}
		
		void sha2_update(array<word32, 8>& H, const array<word32, 16>& M)
		{
			sha2_transform<64>(H, M, K32);
		}

		void sha2_update(array<word64, 8>& H, const array<word64, 16>& M)
		{
			sha2_transform<80>(H, M, K64);
		}

		void sha2_finish(array<word32, 8>& H, const void* data, size_t size, msize_type message_size)
		{
			sha2_finish_impl(H, data, size, message_size);
		}

		void sha2_finish(array<word64, 8>& H, const void* data, size_t size, msize_type message_size)
		{
			sha2_finish_impl(H, data, size, message_size);
		}

		msize_type safe_add(msize_type s, size_t to_add, msize_type max)
		{
			auto r = s + to_add;
#if defined SHA2_CARE_ABOUT_INTEGER_OVERFLOW
			if (r < s || r > max)
			{
#if defined SHA2_HASH_USE_EXCEPTIONS_FOR_OVERFLOW
				throw std::overflow_error("Message size overflow.");
#endif
				assert(false && "Message size overflow.");
				std::terminate();
			}
#endif
			return r;
		}
	}
}

	// Completely unoptimized version, in case someone is interested.

	//template <size_t Rounds, typename Word, typename Constants>
	//void gensha2impl(array<Word, 8>& H, const array<Word, 16>& M, Constants K)
	//{
	//	static_assert(Rounds >= 16 && Rounds % 16 == 0, "Rounds must be 16 or higher.");

	//	array<Word, Rounds> W;

	//	for (size_t t = 0; t != 16; ++t)
	//		W[t] = swap_bytes(M[t]);

	//	for (size_t t = 16; t != Rounds; ++t)
	//	{
	//		W[t + 0] = s1(W[t + 0 - 2]) + W[t + 0 - 7] + s0(W[t + 0 - 15]) + W[t + 0 - 16];
	//	}

	//	Word a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

	//	for (size_t t = 0; t != Rounds; ++t)
	//	{
	//		Word t1 = h + S1(e) + ch(e, f, g) + K[t] + W[t];
	//		Word t2 = S0(a) + maj(a, b, c);
	//		h = g;
	//		g = f;
	//		f = e;
	//		e = d + t1;
	//		d = c;
	//		c = b;
	//		b = a;
	//		a = t1 + t2;
	//	}

	//	H[0] += a;
	//	H[1] += b;
	//	H[2] += c;
	//	H[3] += d;
	//	H[4] += e;
	//	H[5] += f;
	//	H[6] += g;
	//	H[7] += h;
	//}
