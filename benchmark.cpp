/* 
 * Small and messy benchmark file.
 * Compile with Visual Studio 2012 or
 * GCC with: g++ -std=c++11 -Wall -pedantic -O4
 * And optionally -march=native
 * 
 */

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <random>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>

#include "sha2.hpp"

template <typename Clock = std::chrono::high_resolution_clock>
class stopwatch
{
public:
	typedef typename Clock::time_point time_point;
	typedef typename Clock::duration duration;

private:
	time_point last_;

public:
	stopwatch()
		: last_(Clock::now())
	{}

	void reset()
	{
		*this = stopwatch();
	}

	duration elapsed() const
	{
		return Clock::now() - last_;
	}

	duration tick()
	{
		auto now = Clock::now();
		auto elapsed = now - last_;
		last_ = now;
		return elapsed;
	}
};

template <typename T, typename Rep, typename Period>
T duration_cast(const std::chrono::duration<Rep, Period>& duration)
{
    return duration.count() * static_cast<T>(Period::num) / static_cast<T>(Period::den);
}

template <typename Hash>
void print_hash(std::ostream& stream, Hash hash)
{
	using namespace std;

	for (auto b : hash)
	{
		stream << setfill('0') << setw(2) << hex << static_cast<unsigned>(b);
	}

	stream << dec; // O_o
}

void benchmark()
{
	using namespace std;
	using namespace sha2;

	const auto maxd = chrono::milliseconds(777);
	const size_t bytes = 1 << 16;

	default_random_engine e;
	uniform_int_distribution<char> d(' ', '~');
	string s(bytes, ' ');

	for (auto& c : s)
		c = d(e);

	for (size_t i = 2; i != bytes; i = i * 2)
	{
		vector<sha256_hash> hashes;
		stopwatch<> sw;

		size_t j = 0;
		do hashes.push_back(sha256(s.data(), i)), j += i;
		while (sw.elapsed() < maxd);

		double t = duration_cast<double>(sw.elapsed());
		t *= 1024 * 1024;
		cout << "SHA256 - " << i << " byte messages:\t" << setprecision(5) << j / t << "\tMB/s\n";
	}

	for (size_t i = 2; i != bytes; i = i * 2)
	{
		vector<sha512_hash> hashes;
		stopwatch<> sw;

		size_t j = 0;
		do hashes.push_back(sha512(s.data(), i)), j += i;
		while (sw.elapsed() < maxd);

		double t = duration_cast<double>(sw.elapsed());
		t *= 1024 * 1024;
		cout << "SHA512 - " << i << " byte messages:\t" << setprecision(5) << j / t << "\tMB/s\n";
	}
}

void benchlong()
{
	using namespace std;
	using namespace sha2;

	const size_t m_size = 128;
	const size_t size = m_size * 1024 * 1024;

	default_random_engine e;
	uniform_int_distribution<char> d(' ', '~');
	string s(size, ' ');

	for (auto& c : s)
		c = d(e);

	{
		stopwatch<> sw;
		auto hash = sha256(s.data(), s.size());
		double t = duration_cast<double>(sw.elapsed());
		cout << "sha256:\t\t\t" << setprecision(5) << m_size / t << "\tMB/s\n";
		print_hash(cout, hash);
		cout << '\n';
	}

	{
		typedef sha256_raw_hasher::block_type block;
		sha256_raw_hasher hasher;
		const size_t blocks = s.size() / sizeof(block);
		const size_t rest = s.size() % sizeof(block);
		stopwatch<> sw;
		hasher.update(reinterpret_cast<const block*>(s.data()), s.size() / sizeof(block));
		auto hash = hasher.finish(s.data() + blocks * sizeof(block), rest);
		double t = duration_cast<double>(sw.elapsed());
		cout << "sha256_raw_hasher:\t" << setprecision(5) << m_size / t << "\tMB/s\n";
		print_hash(cout, hash);
		cout << '\n';
	}

	{
		typedef sha256_hasher::block_type block;
		sha256_hasher hasher;
		stopwatch<> sw;
		hasher.update(s.data(), s.size());
		auto hash = hasher.finish();
		double t = duration_cast<double>(sw.elapsed());
		cout << "sha256_hasher:\t\t" << setprecision(5) << m_size / t << "\tMB/s\n";
		print_hash(cout, hash);
		cout << '\n';
	}

	{
		stopwatch<> sw;
		auto hash = sha512(s.data(), s.size());
		double t = duration_cast<double>(sw.elapsed());
		cout << "sha512:\t\t\t" << setprecision(5) << m_size / t << "\tMB/s\n";
		print_hash(cout, hash);
		cout << '\n';
	}

	{
		typedef sha512_raw_hasher::block_type block;
		sha512_raw_hasher hasher;
		const size_t blocks = s.size() / sizeof(block);
		const size_t rest = s.size() % sizeof(block);
		stopwatch<> sw;
		hasher.update(reinterpret_cast<const block*>(s.data()), s.size() / sizeof(block));
		auto hash = hasher.finish(s.data() + blocks * sizeof(block), rest);
		double t = duration_cast<double>(sw.elapsed());
		cout << "sha512_raw_hasher:\t" << setprecision(5) << m_size / t << "\tMB/s\n";
		print_hash(cout, hash);
		cout << '\n';
	}

	{
		typedef sha512_hasher::block_type block;
		sha512_hasher hasher;
		stopwatch<> sw;
		hasher.update(s.data(), s.size());
		auto hash = hasher.finish();
		double t = duration_cast<double>(sw.elapsed());
		cout << "sha512_hasher:\t\t" << setprecision(5) << m_size / t << "\tMB/s\n";
		print_hash(cout, hash);
		cout << '\n';
	}
}

int main()
{
	using namespace std;
	using namespace sha2;

	cout << "Enter 'file' to hash a file, 'string' to hash a string, 'bench' "
	        "to run a benchmark or benchlong to benchmark different hashers.\n";

	string s;
	while (cout << "#> " && getline(cin, s))
	{
		if (s == "file")
		{
			if (cout << "filename: " && getline(cin, s))
			{
				ifstream file(s, ifstream::binary | ifstream::in);

				if (file.is_open())
				{
					sha256_hasher hasher256;
					sha512_hasher hasher512;
					array<char, 0x1000> buf;

					while (file.read(buf.data(), buf.size()))
					{
						hasher256.update(buf.data(), static_cast<size_t>(file.gcount()));
						hasher512.update(buf.data(), static_cast<size_t>(file.gcount()));
					}

					hasher256.update(buf.data(), static_cast<size_t>(file.gcount()));
					hasher512.update(buf.data(), static_cast<size_t>(file.gcount()));

					auto hash256 = hasher256.finish();
					auto hash512 = hasher512.finish();

					if (!file.eof())
						cerr << "Warning: Did not reach end of file.\n";

					cout << "SHA256: ";
					print_hash(cout, hash256);
					cout << '\n';
					cout << "SHA512: ";
					print_hash(cout, hash512);
					cout << '\n';
				}
				else
				{
					cerr << "Could not open file " << s << '\n';
				}
			}
		}
		else if (s == "string")
		{
			if (cout << "string: " && getline(cin, s))
			{
				auto hash256 = sha256(s.data(), s.size());
				auto hash512 = sha512(s.data(), s.size());

				cout << "SHA256: ";
				print_hash(cout, hash256);
				cout << '\n';
				cout << "SHA512: ";
				print_hash(cout, hash512);
				cout << '\n';
			}
		}
		else if (s == "bench" || s == "benchmark")
		{
			benchmark();
		}
		else if (s == "benchlong")
		{
			benchlong();
		}
		else if (s != "")
		{
			cerr << "Unkown command: " << s << '\n';
		}
	}
}
