#include "algorithm/hmac.h"
#include "algorithm/pbkdf2.h"
#include "algorithm/sha256.h"
#include "util/helper.h"

int main() {
  std::string password;
  std::vector<std::byte> salt;

  std::shared_ptr<file_encrypt::algorithm::HMAC> hmac =
      std::make_shared<file_encrypt::algorithm::HMAC>(
          std::make_unique<file_encrypt::algorithm::SHA256>());

  // test 1
  {
    password = "7DHd7pbx;suX.a3";
    salt = file_encrypt::util::HexStrToBytes(
        "4AD9A7BA390574A2DB5330BAEA64894F8F881CD67B842DD23393");
    std::array<std::byte, 16> key = file_encrypt::util::HexStrToBytes<16>(
        "07BABF16773F6DFE4D1F08D231F40340");

    auto result =
        file_encrypt::algorithm::PBKDF2<128>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 2
  {
    password = "password";
    salt = file_encrypt::util::StrToBytes("salt");
    std::array<std::byte, 20> key = file_encrypt::util::HexStrToBytes<20>(
        "120fb6cffcf8b32c43e7225256c4f837a86548c9");

    auto result = file_encrypt::algorithm::PBKDF2<160>(password, salt, hmac, 1);
    if (result != key) return -1;
  }
  // test 3
  {
    password = "N8WdLHThOIE;JQ!&:QOQ/q";
    salt = file_encrypt::util::HexStrToBytes(
        "9CDCF60BD0E61FF1399C6DF986BE2B947BD25A0C44");
    std::array<std::byte, 24> key = file_encrypt::util::HexStrToBytes<24>(
        "957638CF44D50AEEC390871E271D6D6F17751525E1A1022F");

    auto result =
        file_encrypt::algorithm::PBKDF2<192>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 4
  {
    password = "$9e\"#MDqE#D-7V6";
    salt = file_encrypt::util::HexStrToBytes(
        "A2513D7FDAD56DFD750CF90A7BA65F78918A7C04861CB7C62ABB7CCB");
    std::array<std::byte, 32> key = file_encrypt::util::HexStrToBytes<32>(
        "340A103BCE1389A04DF1D0B6DC5D5CE7F7577F8C0831F49CDE87BFE7274676FE");

    auto result =
        file_encrypt::algorithm::PBKDF2<256>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 5
  {
    password = ";eJSAg',4+xKN1wt3Sp9BkiO\"Lv";
    salt = file_encrypt::util::HexStrToBytes(
        "B7C2226C7EE7794F5EEEB2FE8713A53FB6EF180E08F9373F104C");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "D3F78AE4B5F195CA5D7B1C8520FFC1EAEEE0CCC7ECD35DB708C443FF04CD73F726BAF7"
        "C6E39C367C7F45B3471559D232");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 6
  {
    password = "dehWcr,HFM@5aV3HbR9-Suz";
    salt = file_encrypt::util::HexStrToBytes(
        "625D09DCD1D29B8DC3302F0FC3DD5C2BC51249FEC5ED6EAAAAC29F4B70B3462D");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "CB8B1BAF73E4753A401F5C4E38881191C99C9F876D4296A96C12CDCB049C3C45A35A44"
        "C3B5B2288C0C11BC31471FC416");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 7
  {
    password = "?!:%YqWBaH0qy2Yb4ljm@1cFg9OGHvO";
    salt = file_encrypt::util::HexStrToBytes(
        "18B63D739F23302EEFEDE036D58099F22C173B12F680EE72AC1F");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "FB93CD3B95DC66D538B96C0CC8B53FB60A57E78E5C689EE2350F1DECC060550D50901E"
        "68D8760EBEB1F1F72CB50D3A45");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 8
  {
    password = "\"5T4b*'0\"OU";
    salt = file_encrypt::util::HexStrToBytes(
        "CCF736EA69441A198C105CA33D4DF331D406904519F2DC71A94900C79C");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "BB2873A5FD607D26855880023E16E1D4A676143B617AE7473FABFB9A569EF7381CD529"
        "FD9FE43EDFA05D97318B7C2AD0");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 9
  {
    password = "hmB2%zQ!zJa;LPp";
    salt = file_encrypt::util::HexStrToBytes(
        "63BF9583D539F1530032E131951E575DAC4AC09CC3");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "48D796420595A13B986A45605AED184E71D641C71EFB422AD3283454FF2A5E32E5FC2A"
        "7C362A4A6E2A2BC1DCD7D678A6");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 10
  {
    password = "NNVQPSR3w!qA";
    salt = file_encrypt::util::HexStrToBytes(
        "CCF8D4111C2A20D23028B88CB7B5ECA68A17724A3D64A0");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "E113C4ED782376D7C51E240367F1C34FB6C1CDEDEC72A612930BDD9DAF0B21DA8B4850"
        "3819A9B74B7B38E4ED39357A53");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 11
  {
    password = "%2@,JT0#K#!$.74y!N05l?R";
    salt = file_encrypt::util::HexStrToBytes(
        "BFD51C9C4E16D4432D3E4E4518EB3BE161F6A44789B123FE0D6D528382408433");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "E062BF2121022629DB4831AD475C2AECED8CCF38A282A7F8D2F9FE1E64A49936BF4476"
        "CB52EE9352F9D81CBFD1909684");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 12
  {
    password = "e2/!*vhne'Q.M";
    salt = file_encrypt::util::HexStrToBytes(
        "EDFDE1A8EE7C1E08C93C2F22D544D24B69A1AD1E");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "A935536DABA82423062927FF1FE96A393B874EA62B9911DFE4D858B27B406F55534393"
        "6F96CC76D8124CD909E09A6ABD");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 13
  {
    password = "qku9P$Z,gl9pK";
    salt = file_encrypt::util::HexStrToBytes(
        "F3FD77B2BA6D2110D4C1784C984B9DD7459AED6C38E7D496");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "4B6738AEFCA83F316D1F5C241A0793E147ACAF06D6F8FA99C7D9F31933076285AD85BF"
        "9717FBC0953F311555FBE0A30D");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 14
  {
    password = "s/i3V#JO?DUV6R35Yq7fUCu5j9QM";
    salt = file_encrypt::util::HexStrToBytes(
        "E3555B294CA8F5DBF6B20373296B255FAA4F7F87D819692EF4CF");
    std::array<std::byte, 48> key = file_encrypt::util::HexStrToBytes<48>(
        "5CB139C8F4D1EBE0017CB34486069C66E9DA9A60EDCB60BB97163AC0C293769C8C5215"
        "BD4DCB9528FED8263E383C385C");

    auto result =
        file_encrypt::algorithm::PBKDF2<384>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 15
  {
    password = "SpkkrU1hoA6JKiZkw9Px!TMrYj$vRnU*";
    salt = file_encrypt::util::HexStrToBytes(
        "F5C7CE36B874264F4E51F5F076EF14E7DC1FA515");
    std::array<std::byte, 64> key = file_encrypt::util::HexStrToBytes<64>(
        "46A8F43C883AE72866BE252EE32AF00FA4209FD92EB907C2FCBD29447190C4B2F0CB5E"
        "1B92968E77716160B55B6DC46D2E133FFD7B86A70B60D8827AF9889DFF");

    auto result =
        file_encrypt::algorithm::PBKDF2<512>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 16
  {
    password = "K60@6UavDl1tpVv\"856.NLg";
    salt = file_encrypt::util::HexStrToBytes(
        "CDE1BD4DE33D0B812CF375D99E71C7C47D378C6FD081248B1526165034C0A7C2");
    std::array<std::byte, 96> key = file_encrypt::util::HexStrToBytes<96>(
        "40973544B8091D49232231B2716AF9C08305C4939BB41448E5FBDFB028EF0273883568"
        "27140DFF9A7664AC1894CB18E291635F7FD633A0814038A75380F5BC2F97E589130F9B"
        "0E502420B90B64EA9B82F84E5A24860A59A110E13428EDDEBF98");

    auto result =
        file_encrypt::algorithm::PBKDF2<768>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 17
  {
    password = "l\"FwgM,kdkh7RE\"3+QfGY";
    salt = file_encrypt::util::HexStrToBytes(
        "41AA12E0958829C9959BF591F39DDB5D5276B1FB580173C6051338CA43BA");
    std::array<std::byte, 128> key = file_encrypt::util::HexStrToBytes<128>(
        "F585C64B198A132F52A620879AAF4BBE110AACD6CF316D9BEFB4D9D7062D58847492E4"
        "606FB1482EC327FE8B08FBCF4C89256A5EBE6810F6632A30141C9AE930E756ECFAD2D1"
        "16A1255513A9FBD64446BDE0FB02E85D5B25226165177916BAB4D0E46FD8F13028024C"
        "D42F8709F0D171AC190F7F304C416907DCB3BE504BDD2C");

    auto result =
        file_encrypt::algorithm::PBKDF2<1024>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 18
  {
    password = "Cwii&\",sUey@AQ'p'#$:r-NuA";
    salt = file_encrypt::util::HexStrToBytes(
        "233F459432AD6A180F108E067785680BEFCCCA80");
    std::array<std::byte, 256> key = file_encrypt::util::HexStrToBytes<256>(
        "88A767FCACA2A3B3492F4A580206F5933D44642CE2A522AD3561AD13874F3FBC50AF34"
        "E870CAB13CF5675F12A1D2B402AF0D32671B6FEC39CE2182335D332574ED6D55885C6A"
        "694E6F0D222CE3F16949AC1B12844F6349711E66581311763388414E5D5C6FC04E0669"
        "0DCE431561E63B97F05791658A42360AA1BA94C9E61E4DC5CAFAD51308B474C90B15AF"
        "01FB87C7657B85A5A4BB0DECF1C38D90A543A4CF28924ADF00E30C3CBD080C70B8B89F"
        "AFC8B210BD5FC981BDFA9B1C909F7A6A6A9B85353E2F1C3549A3E37019A3FCFD33944B"
        "F6420A5D63B52B4316AC8831403CEE6DF3DDEBCC2CF6C08D65551EEFF9B0650218DF7C"
        "B038E7618BA51D46DDE978");

    auto result =
        file_encrypt::algorithm::PBKDF2<2048>(password, salt, hmac, 1011);
    if (result != key) return -1;
  }
  // test 19
  {
    password = "S21?:2LLVWEqiG,";
    salt = file_encrypt::util::HexStrToBytes(
        "B00E43E6ADF72B830F65658C1726D6588D722AFC051D2E1D");
    std::array<std::byte, 256> key = file_encrypt::util::HexStrToBytes<256>(
        "CFA27C1FFEFD26C534260B13C05B42D929EA71686ED7E52BC08EF709265A1370D8669D"
        "B0C02F3A33FDC3134F47D0E3D64FC70689272F1CCC04750136253F6A1B4492C6DD3B80"
        "19B1931F32F4E3FCAAB525DF7357350A6638B4DBEB8729AB25000E798B65D07B055A0D"
        "E4B45D9F1D07C27A91B1BAFC54029385C9E0A6262340529C8BC63BA0F981E78F913F3C"
        "91B822FFF1271A824AEC450CB45FA26631B739120433CA6B99C23A04AD5F769F8E093F"
        "C1EB49BC288D3548703D72739CB826DA52696AB77567596EAC51CF27D847783067DB8B"
        "79F0A4727AE6A30D7E1754C9040A91C9FD2C50E78C49BA07A60BBA58FFC8402EE3CE74"
        "09CD3C7A41A28C4C45F5DA");

    auto result =
        file_encrypt::algorithm::PBKDF2<2048>(password, salt, hmac, 65614);
    if (result != key) return -1;
  }
  return 0;
}