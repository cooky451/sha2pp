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
/* 
 * Secure Hash Standard (SHS) http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
 * 
 * This implementation currently assumes small endian!
 * 
 * Compile with Visual Studio 2012 or
 * GCC with: g++ -std=c++11 -march=native -O4 -Wall -pedantic
 * 
 * Speeds with VS 2012 on a 3570K @3.4GH:
 * x86: SHA256: ~190 MB/s, SHA512: ~70 MB/s
 * x64: SHA256: ~205 MB/s, SHA512: ~312 MB/s
 */

#ifndef SHA2_HASH_HPP
#define SHA2_HASH_HPP

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <array>
#include <limits>

namespace sha2
{
	typedef std::uint8_t byte;
	typedef std::uint32_t word32;
	typedef std::uint64_t word64;
	typedef std::uint64_t msize_type;
	using std::size_t;
	using std::array;

	const auto max_message_size = std::numeric_limits<msize_type>::max() / 8;

	namespace detail
	{
		template <typename Word, size_t DigestBits>
		class basic_raw_hasher;

		template <typename Word, size_t DigestBits>
		class basic_hasher;
	}

	// Use these if you're unsure. They copy the data, but take care of
	// alignment and strict aliasing.
	typedef detail::basic_hasher<word32, 224> sha224_hasher;
	typedef detail::basic_hasher<word32, 256> sha256_hasher;
	typedef detail::basic_hasher<word64, 384> sha384_hasher;
	typedef detail::basic_hasher<word64, 512> sha512_hasher;
	typedef detail::basic_hasher<word64, 224> sha512_224_hasher;
	typedef detail::basic_hasher<word64, 256> sha512_256_hasher;

	// These may be faster.
	typedef detail::basic_raw_hasher<word32, 224> sha224_raw_hasher;
	typedef detail::basic_raw_hasher<word32, 256> sha256_raw_hasher;
	typedef detail::basic_raw_hasher<word64, 384> sha384_raw_hasher;
	typedef detail::basic_raw_hasher<word64, 512> sha512_raw_hasher;
	typedef detail::basic_raw_hasher<word64, 224> sha512_224_raw_hasher;
	typedef detail::basic_raw_hasher<word64, 256> sha512_256_raw_hasher;

	// For convenience.
	void sha224(void* buf, size_t buf_size, const void* data, size_t size);
	void sha256(void* buf, size_t buf_size, const void* data, size_t size);
	void sha384(void* buf, size_t buf_size, const void* data, size_t size);
	void sha512(void* buf, size_t buf_size, const void* data, size_t size);
	void sha512_224(void* buf, size_t buf_size, const void* data, size_t size);
	void sha512_256(void* buf, size_t buf_size, const void* data, size_t size);

	array<byte, 224 / 8> sha224(const void* data, size_t size);
	array<byte, 256 / 8> sha256(const void* data, size_t size);
	array<byte, 384 / 8> sha384(const void* data, size_t size);
	array<byte, 512 / 8> sha512(const void* data, size_t size);
	array<byte, 224 / 8> sha512_224(const void* data, size_t size);
	array<byte, 256 / 8> sha512_256(const void* data, size_t size);
}

namespace sha2
{
	namespace detail
	{
		word32 swap_bytes(word32 w);
		word64 swap_bytes(word64 w);

		void sha2_update(array<word32, 8>& H, const array<word32, 16>& M);
		void sha2_update(array<word64, 8>& H, const array<word64, 16>& M);

		void sha2_finish(array<word32, 8>& H, const void* data, size_t size, msize_type message_size);
		void sha2_finish(array<word64, 8>& H, const void* data, size_t size, msize_type message_size);

		msize_type safe_add(msize_type s, size_t to_add, msize_type max = max_message_size);

		template <typename T, size_t Size>
		size_t bytesize(const array<T, Size>&)
		{
			return sizeof(T) * Size;
		}

		template <typename T>
		struct always_false
		{
			static const bool value = false;
		};

		template <typename Word, size_t DigestBits>
		const array<Word, 8>& H0()
		{
			// Using always_false here so the compiler can only trigger this on instantiation.
			static_assert(always_false<Word>::value, "This word type and digest size combination is not supported.");
		}

		template <>
		const array<word32, 8>& H0<word32, 224>();

		template <>
		const array<word32, 8>& H0<word32, 256>();

		template <>
		const array<word64, 8>& H0<word64, 384>();

		template <>
		const array<word64, 8>& H0<word64, 512>();

		template <>
		const array<word64, 8>& H0<word64, 224>();

		template <>
		const array<word64, 8>& H0<word64, 256>();

		template <typename Word, size_t DigestBits>
		class basic_raw_hasher
		{
		public:
			typedef array<Word, 8> state;
			typedef array<Word, 16> block;

		private:
			state H_;
			msize_type message_size_;

		public:
			basic_raw_hasher()
				: H_(H0<Word, DigestBits>())
				, message_size_()
			{}

			void update(const block& b)
			{
				message_size_ = safe_add(message_size_, sizeof b);
				sha2_update(H_, b);
			}

			void update(const block* data, size_t size)
			{
				while (size-- != 0)
					update(*data++);
			}

			void finish(void* buf, size_t buf_size, const void* data = nullptr, size_t size = 0)
			{
				sha2_finish(H_, data, size, message_size_);
				std::memcpy(buf, &H_[0], std::min(buf_size, bytesize(H_)));
				*this = basic_raw_hasher();
			}

			array<byte, DigestBits / 8> finish(const void* data = nullptr, size_t size = 0)
			{
				array<byte, DigestBits / 8> hash;
				finish(hash.data(), bytesize(hash), data, size);
				return hash;
			}
		};

		template <typename Word, size_t DigestBits>
		class basic_hasher
		{
		public:
			typedef basic_raw_hasher<Word, DigestBits> raw_hasher_type;

			typedef typename raw_hasher_type::block block;
			typedef typename raw_hasher_type::state state;

		private:
			raw_hasher_type hasher_;
			block M_;
			size_t used_;
			
		public:
			basic_hasher()
				: used_()
			{}

			void update(const void* data, size_t size)
			{
				auto fill_size = std::min(bytesize(M_) - used_, size);
				std::memcpy(reinterpret_cast<byte*>(&M_[0]) + used_, data, fill_size);
				used_ += fill_size;

				// At this point the buffer is either full, or there's not more to copy.
				if (used_ == bytesize(M_))
				{
					hasher_.update(M_);

					size -= fill_size;
					data = static_cast<const byte*>(data) + fill_size;					

					auto msize = size / bytesize(M_);
					auto rsize = size % bytesize(M_);

					while (msize-- != 0)
					{
						std::memcpy(&M_[0], data, bytesize(M_));
						hasher_.update(M_);
						data = static_cast<const byte*>(data) + bytesize(M_);
					}
					
					std::memcpy(&M_[0], data, rsize);
					used_ = rsize;
				}
			}

			void finish(void* buf, size_t bufsize)
			{
				hasher_.finish(buf, bufsize, &M_[0], used_);
			}

			array<byte, DigestBits / 8> finish()
			{
				array<byte, DigestBits / 8> hash;
				finish(hash.data(), bytesize(hash));
				return hash;
			}
		};
	}
}

#endif
