#include <cstddef>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "converter.h"
#include "forward_proto.h"
#include "matcher.h"

TEST(test_converter, test_packet_converter)
{
  std::vector<unsigned char> mypkt1 = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x39, 0x00, 0x00, 0x00, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00,
      0x2B, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7C, 0xCA, 0x7F, 0x00,
      0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
      0xCD, 0x16, 0x00, 0x00, 0x61, 0x62, 0x63};
  std::vector<unsigned char> mypkt2 = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x39, 0x00, 0x00, 0x00, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00,
      0x2B, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7C, 0xCA, 0x7F, 0x00,
      0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x31, 0x32, 0x61, 0x62, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
      0xCD, 0x16, 0x00, 0x00, 0x31, 0x32, 0x33};
  std::vector<std::string> signatures = {"abc", "xyz"};
  std::string sample_file = "mysample.rules";
  std::ofstream sample_out(sample_file);
  for (const auto& sig : signatures) {
    sample_out << sig << std::endl;
  }
  sample_out.close();
  PacketConverter pktcon(1);
  pktcon.set_matcher(sample_file, Mode::BLOCK);
  Matcher* mymatcher = pktcon.get_matcher();
  ASSERT_FALSE(mymatcher == nullptr);
  std::remove(sample_file.c_str());
  PackMsg pmsg;
  pmsg.set_max_bytes(241);
  for (int i = 0; i < 45; ++i) {
    Conv::Status mystatus = pktcon.convert(1,
        reinterpret_cast<char*>(mypkt1.data()), mypkt1.size(), pmsg);
    EXPECT_EQ(mystatus, Conv::Status::Pass);
    mystatus = pktcon.convert(2, reinterpret_cast<char*>(mypkt2.data()),
                              mypkt2.size(), pmsg);
    EXPECT_EQ(mystatus, Conv::Status::Success);
  }
  EXPECT_EQ(pmsg.get_entries(), 1);
  std::stringstream mystream;
  pmsg.pack(mystream);
  std::string mypmstring = pmsg.get_string(mystream);
  EXPECT_TRUE(mypmstring.find(R"("sport":"12")") != std::string::npos);
  EXPECT_TRUE(mypmstring.find(R"("dport":"ab")") != std::string::npos);
}

TEST(test_converter, test_vlan_converter)
{
  std::vector<unsigned char> mypkt1 = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39,
      0x00, 0x00, 0x00, 0x39, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x20, 0x08, 0x00, 0x45, 0x00,
      0x00, 0x2B, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7C, 0xCA, 0x7F, 0x00,
      0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xCD, 0x16,
      0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
      0x6B, 0x6C, 0x6D, 0x6E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
      0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
      0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x61, 0x62, 0x63, 0x64,
      0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x61, 0x62,
      0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
      0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
      0x6D, 0x6E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
      0x6B, 0x6C, 0x6D, 0x6E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
      0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
      0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x65, 0x65};

  PacketConverter pktcon(1);
  PackMsg pmsg;
  pmsg.set_max_bytes(234);
  Conv::Status mystatus = pktcon.convert(1, reinterpret_cast<char*>(mypkt1.data()),
                                         mypkt1.size(), pmsg);
  std::stringstream mystream;
  pmsg.pack(mystream);
  EXPECT_EQ(pmsg.get_entries(), 1);
  std::string mypmstring = pmsg.get_string(mystream);
  EXPECT_EQ(mystatus, Conv::Status::Success);
  std::string msg =
      "\"message\":"
      "\"abcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmn"
      "abcdefghijklmnabcdefghijklmnabcdefghijklmnabcdefghijklmnee\"";
  EXPECT_TRUE(mypmstring.find(msg) != std::string::npos);
}

TEST(test_converter, test_log_converter)
{
  std::string msg1 = "here is my message abc";
  std::string msg2 = "123 message 2 should not match!";
  std::vector<std::string> signatures = {"abc", "xyz"};
  std::string sample_file = "mysample.rules";
  std::ofstream sample_out(sample_file);
  for (const auto& sig : signatures) {
    sample_out << sig << std::endl;
  }
  sample_out.close();
  LogConverter logcon;
  logcon.set_matcher(sample_file, Mode::BLOCK);
  Matcher* mymatcher = logcon.get_matcher();
  ASSERT_FALSE(mymatcher == nullptr);
  std::remove(sample_file.c_str());
  PackMsg pmsg;
  Conv::Status mystatus =
      logcon.convert(1, reinterpret_cast<char*>(msg1.data()), msg1.size(), pmsg);
  EXPECT_EQ(mystatus, Conv::Status::Pass);
  mystatus =
      logcon.convert(2, reinterpret_cast<char*>(msg2.data()), msg2.size(), pmsg);
  EXPECT_EQ(mystatus, Conv::Status::Success);
  EXPECT_EQ(pmsg.get_entries(), 1);
}

TEST(test_converter, test_entropy)
{
  std::vector<unsigned char> mypkt1 = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB6,
      0x00, 0x00, 0x00, 0xB6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0xA8, 0x00, 0x01,
      0x00, 0x00, 0x40, 0x06, 0x7C, 0xCA, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00,
      0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xCD, 0x16, 0x00, 0x00, 0x01, 0x02,
      0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
      0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
      0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
      0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
      0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
      0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56,
      0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62,
      0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
      0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
      0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80};
  std::vector<unsigned char> mypkt2 = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB6,
      0x00, 0x00, 0x00, 0xB6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0xA8, 0x00, 0x01,
      0x00, 0x00, 0x40, 0x06, 0x7C, 0xCA, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00,
      0x00, 0x01, 0x00, 0x15, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0xCD, 0x16, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
      0x61, 0x61, 0x61, 0x61, 0x61, 0x61};

  PacketConverter pktcon(1);
  pktcon.set_allowed_entropy_ratio(0.75);
  PackMsg pmsg;
  pmsg.set_max_bytes(256);
  Conv::Status mystatus = pktcon.convert(1, reinterpret_cast<char*>(mypkt1.data()),
                                         mypkt1.size(), pmsg);
  EXPECT_EQ(mystatus, Conv::Status::Success);
  EXPECT_EQ(pmsg.get_entries(), 0);
  mystatus = pktcon.convert(2, reinterpret_cast<char*>(mypkt2.data()),
                            mypkt2.size(), pmsg);
  EXPECT_EQ(mystatus, Conv::Status::Success);
  EXPECT_EQ(pmsg.get_entries(), 1);
}
