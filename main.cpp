#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted_data)
{
    // https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/7e9d84fe-86e3-46d6-aaff-8388e72c0168
    // https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/a2ad3aa7-e180-4ccb-8511-7e0eb49a0ad9

    if(encrypted_data.size() < 7)
    {
        throw std::invalid_argument("input size not plausible");
    }

    uint8_t Seed = encrypted_data[0];
    uint8_t VersionEnc = encrypted_data[1];
    uint8_t ProjKeyEnc = encrypted_data[2];

    uint8_t Version = Seed ^ VersionEnc;
    if(Version != 2)
    {
        throw std::invalid_argument("input seems corrupted, Version MUST be 2");
    }

    uint8_t ProjKey = Seed ^ ProjKeyEnc;

    uint8_t EncryptedByte1 = ProjKeyEnc;
    uint8_t EncryptedByte2 = VersionEnc;
    uint8_t UnencryptedByte1 = ProjKey;

    uint8_t IgnoredLength = (Seed & 6) / 2;
    for(auto i = 0; i < IgnoredLength; i++)
    {
        uint8_t ByteEnc = encrypted_data[i+3];
        uint8_t Byte = ByteEnc ^ (EncryptedByte2 + UnencryptedByte1);
        EncryptedByte2 = EncryptedByte1;
        EncryptedByte1 = ByteEnc;
        UnencryptedByte1 = Byte;
    }

    auto DataLengthEncOffset = 3+IgnoredLength;
    auto DataEncOffset = DataLengthEncOffset+4;
    std::vector<uint8_t> DataLengthEnc(encrypted_data.begin() + DataLengthEncOffset, encrypted_data.begin() + DataEncOffset);
    uint32_t Length = 0;
    for(auto i = 0; i < 4; i++)
    {
        uint8_t ByteEnc = DataLengthEnc[i];
        uint8_t Byte = ByteEnc ^ (EncryptedByte2 + UnencryptedByte1);
        uint32_t TempValue = 1 << (i*8);
        TempValue *= Byte;
        Length += TempValue;
        EncryptedByte2 = EncryptedByte1;
        EncryptedByte1 = ByteEnc;
        UnencryptedByte1 = Byte;
    }

    std::vector<uint8_t> Data;
    for(auto i = DataEncOffset; i < encrypted_data.size(); i++)
    {
        uint8_t ByteEnc = encrypted_data[i];
        uint8_t Byte = ByteEnc ^ (EncryptedByte2 + UnencryptedByte1);
        Data.push_back(Byte);
        EncryptedByte2 = EncryptedByte1;
        EncryptedByte1 = ByteEnc;
        UnencryptedByte1 = Byte;
    }

    return Data;
}

std::vector<uint8_t> decode_nulls(const std::vector<uint8_t>& encoded, const std::vector<bool>& GrbitNull)
{
    // https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/5797c2e1-4c86-4f44-89b4-1edb30da00cc
    // we assume here that GrbitNull is a bool vector, rather than single bits. the translation has to be done before calling decode_nulls

    if(encoded.size() != GrbitNull.size())
    {
        throw std::invalid_argument("input sizes do not match - not plausible");
    }

    std::vector<uint8_t> DecodedBytes;
    for(int i = 0; i < GrbitNull.size(); i++)
    {
        DecodedBytes.push_back(GrbitNull[i] ? encoded[i] : (uint8_t) 0);
    }
    return DecodedBytes;
}

std::vector<uint8_t> get_sha1(const std::vector<uint8_t>& password_hash)
{
    // extract the SHA-1 hash from a Password Hash Data structure
    // https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/9d9f81e6-f92e-4338-a242-d38c1fcceed6

    std::vector<uint8_t> PasswordHashNoNulls(password_hash.begin() + 8, password_hash.begin() + 28);
    std::vector<bool> GrbitHashNull;

    GrbitHashNull.push_back(password_hash[1] & 8);
    GrbitHashNull.push_back(password_hash[1] & 4);
    GrbitHashNull.push_back(password_hash[1] & 2);
    GrbitHashNull.push_back(password_hash[1] & 1);
    for(auto i = password_hash.begin() + 2; i < password_hash.begin() + 4; i++)
    {
        for(auto j = 1; j < 256; j = j << 1)
        {
            GrbitHashNull.push_back(*i & j);
        }
    }
    
    return decode_nulls(PasswordHashNoNulls, GrbitHashNull);
}

std::vector<uint8_t> get_key(const std::vector<uint8_t>& password_hash)
{
    // extract the key from a Password Hash Data structure
    // https://docs.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/9d9f81e6-f92e-4338-a242-d38c1fcceed6
    std::vector<uint8_t> KeyNoNulls(password_hash.begin() + 4, password_hash.begin() + 8);
    std::vector<bool> GrbitKey;

    uint8_t GrbitKeyBits = password_hash[1] >> 4;
    GrbitKey.push_back(GrbitKeyBits & 8);
    GrbitKey.push_back(GrbitKeyBits & 4);
    GrbitKey.push_back(GrbitKeyBits & 2);
    GrbitKey.push_back(GrbitKeyBits & 1);

    return decode_nulls(KeyNoNulls, GrbitKey);
}

std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    // credit: https://stackoverflow.com/a/30606613
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

void to_console(std::vector<uint8_t> data)
{
    // print readable output to console
    for(auto const& Byte : data)
    {
        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << (uint32_t) Byte;
    }
    std::cout << std::endl;
}

int main(int argc, char const *argv[])
{
    if(argc < 1)
    {
        std::cout << "please call this program with the DPB value as a parameter. example:" << std::endl;
        std::cout << "./decrypt FCFE5054B04FCD4FCDB03350CD27DCB79AACA3F42F5179FFF4B1A293D0B04861AA321BF5767C" << std::endl;
        /*
        for my own future reference, the above example was obtained using the password "12345" and should always yield the following values:
        decrypted:  ffffffff68e9a7197cb595175af0bec373c5e5575a62731140f1d68700
        key:        68e9a719
        sha1:       7cb595175af0bec373c5e5575a62731140f1d687
        */
        return 0;
    }

    std::string encrypted_hex = argv[1];
    if( (encrypted_hex.length() % 2) != 0 )
    {
        encrypted_hex.insert(0, 1, '0');
    }
    std::cout << encrypted_hex << std::endl << std::endl;

    std::vector<uint8_t> encrypted = HexToBytes(encrypted_hex);
    auto decrypted = decrypt(encrypted);
    auto key = get_key(decrypted);
    auto sha1 = get_sha1(decrypted);
    to_console(decrypted);
    to_console(key);
    to_console(sha1);

    return 0;
}