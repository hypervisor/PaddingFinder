#include <iostream>
#include <fstream>
#include <memory>
#include <cstdint>
#include <Windows.h>

int main(int argc, char *argv[])
{
	int32_t min_pad = 1;

	if (argc > 2)
	{
		min_pad = std::strtol(argv[2], nullptr, 0);
		if (min_pad < 1)
			min_pad = 1;
	}

	std::ifstream ifs(argv[1],
		std::ios::in		|
		std::ios::binary	|
		std::ios::ate);

	const auto file_len = ifs.tellg();
	ifs.seekg(0, ifs.beg);

	const auto buffer = std::unique_ptr<uint8_t[]>(new uint8_t[file_len]);

	ifs.read(reinterpret_cast<char *>(buffer.get()), file_len);

	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.get());
	
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		std::cerr << "[!] File is not a valid PE image! (Invalid e_lfanew)" << std::endl;

		return 1;
	}

	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer.get() + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cerr << "[!] File is not a valid PE image! (Invalid NtHeaders->Signature)" << std::endl;

		return 1;
	}

	const auto get_pad_count = [](uint8_t *buffer)
	{
		auto start = buffer;
		for (; *buffer == 0xCC; buffer++);
		return buffer - start;
	};

	const auto base_of_code = buffer.get() + nt_headers->OptionalHeader.BaseOfCode;
	const auto size_of_code = nt_headers->OptionalHeader.SizeOfCode;
	uint64_t total_padding_sections = 0;
	uint64_t total_padding = 0;

	for (uintptr_t i = 0; i < size_of_code; ++i)
	{
		const auto address = reinterpret_cast<uint8_t *>(base_of_code + i);
		const auto padding = get_pad_count(address);

		if (padding >= min_pad)
		{
			const auto rva = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(buffer.get());
			std::cout << "[+] Padding found at rva " << std::hex << rva << " (" << padding << " bytes long)" << '\n';
			total_padding_sections++;
			total_padding += padding;
		}
	}

	std::cout << "[+] Found a total of " << total_padding_sections << " padding sections, with " << total_padding << " bytes in total." << std::endl;
	std::cin.get();

	return 0;
}