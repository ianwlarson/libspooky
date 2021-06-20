#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "spooky.h"

static inline uint32_t
xorshift32(uint32_t *const p_rng)
{
    uint32_t x = *p_rng;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *p_rng = x;
    return *p_rng;
}

static inline void
randfill(void *const p_dst, uint64_t const p_nbytes, uint32_t p_seed)
{
    if (p_seed == 0) {
        p_seed = 0xdeadbeef;
    }

    unsigned *l_dst = p_dst;
    int leftover = p_nbytes & (sizeof(unsigned) - 1);
    uint64_t const end = p_nbytes / sizeof(uint32_t);
    for (uint64_t i = 0; i < end; ++i) {
        l_dst[i] = xorshift32(&p_seed);
    }
    if (leftover > 0) {
        uint32_t const v = xorshift32(&p_seed);
        memcpy(&l_dst[end], &v, leftover);
    }
}

#define DATASIZE 0x10000 // 64k

static uint64_t const expected_values[] = {
    UINT64_C(0x4a21d20d5559a9d2),	UINT64_C(0x64c465dc62e52c7b),
    UINT64_C(0x705bff4f746700a7),	UINT64_C(0x14e2b186f0a1bef2),
    UINT64_C(0x90f73dfe841541f9),	UINT64_C(0x7b702a666bab70b0),
    UINT64_C(0x4317d3c81828acc9),	UINT64_C(0x146bd08ae2120c33),
    UINT64_C(0x79e30be778797ed1),	UINT64_C(0x0d428e0c366ca96b),
    UINT64_C(0x52eb28acfcc4baee),	UINT64_C(0xd328097fdaf3642d),
    UINT64_C(0xe5f4062fa172d468),	UINT64_C(0xe343176338ae5124),
    UINT64_C(0xcdf2c7d555f0f309),	UINT64_C(0x28cd040ec189ed8b),
    UINT64_C(0xa6bc5ad426e7f815),	UINT64_C(0x8539c719dffeeaeb),
    UINT64_C(0x4fe04ddfd15426cf),	UINT64_C(0xe8125e45e58efa5a),
    UINT64_C(0x9f8cb03433641251),	UINT64_C(0xa0fa8fde5ee60cfa),
    UINT64_C(0xff53c4e490d66110),	UINT64_C(0x58d774f86184bf73),
    UINT64_C(0x7e3c049756d52059),	UINT64_C(0x1394e946d4beb4fc),
    UINT64_C(0x15d41627148c5bae),	UINT64_C(0x4c9f822a961bcb2d),
    UINT64_C(0x61f82f159900529f),	UINT64_C(0xc55ccdeeb8f8f20b),
    UINT64_C(0xc659be53e70bd4a3),	UINT64_C(0xe20a30d017ed1237),
    UINT64_C(0xfb309d0ddebd3bbd),	UINT64_C(0x5ee958e7bef6039e),
    UINT64_C(0x589dac43abade672),	UINT64_C(0x13f0e6f576640ce3),
    UINT64_C(0x62a5d1e0a0192cb6),	UINT64_C(0x4d7ab7b0bc412541),
    UINT64_C(0x17c6027c3638add8),	UINT64_C(0x17557d27a315c77c),
    UINT64_C(0x107a5385c41a3a39),	UINT64_C(0x4dc361633c99f1d5),
    UINT64_C(0x57e90e35a0762886),	UINT64_C(0xb558a855c0a1f667),
    UINT64_C(0x19ffb90238f96647),	UINT64_C(0x3a379f142f59484c),
    UINT64_C(0xa061dcf270ab15e3),	UINT64_C(0x79d669b2a6dfe376),
    UINT64_C(0xfdf36ec981b3084b),	UINT64_C(0xe6ec34ddfa51b404),
    UINT64_C(0xcebd767e8e5b467d),	UINT64_C(0xd3d96a8b86491082),
    UINT64_C(0x95ab684e95793101),	UINT64_C(0x2229176b81986b82),
    UINT64_C(0x4bf32f9dbe707d78),	UINT64_C(0x08b3d03aa542d628),
    UINT64_C(0x03798a2affe1e6fa),	UINT64_C(0x768a57ce068eb7ab),
    UINT64_C(0x10a3362eaf38e859),	UINT64_C(0x7ae5e8452b250a95),
    UINT64_C(0x8f43b4058f62b6d7),	UINT64_C(0x18ff9343e64fabb0),
    UINT64_C(0x1b504f7a587b70d1),	UINT64_C(0xaee095a5d8853b20),
    UINT64_C(0xbd5e6e8322caa247),	UINT64_C(0x086fa07a8ae28091),
    UINT64_C(0x0ed282e322e017d5),	UINT64_C(0x4a57c697e3998f1e),
    UINT64_C(0x44e4347b63cde8b1),	UINT64_C(0xff4f48580628dc00),
    UINT64_C(0xdb4eec9bc8ff4224),	UINT64_C(0xcd09b26e35d20cee),
    UINT64_C(0x6f72bee0cfec371f),	UINT64_C(0x42e40e5bbf3fb2b5),
    UINT64_C(0x6d0258a80432328b),	UINT64_C(0x59e02cf28170b560),
    UINT64_C(0x133a4d05759c7cdc),	UINT64_C(0x7261bb1ca7baf5f2),
    UINT64_C(0xd922e36764da7968),	UINT64_C(0x283905e151de278b),
    UINT64_C(0xf2ce607bf9761a19),	UINT64_C(0xa09b98dc92c47db0),
    UINT64_C(0xed374f1c89010d38),	UINT64_C(0x4e655be90573e4ef),
    UINT64_C(0x2ad93810d1e8d498),	UINT64_C(0xee909996c7f12748),
    UINT64_C(0x4c54339ec52638b0),	UINT64_C(0x43fdb0f6de5526ea),
    UINT64_C(0x5e0cf3bb814d73ee),	UINT64_C(0xab47e21d0b06f084),
    UINT64_C(0xd67744931d77f79b),	UINT64_C(0xbf7fc576263ae31e),
    UINT64_C(0x8b14534ca364d16d),	UINT64_C(0x2b0196ad1aa1c2ec),
    UINT64_C(0x72e6256fe10b3af7),	UINT64_C(0x176308aa53be2df7),
    UINT64_C(0xde91155c7619aad3),	UINT64_C(0xa83221f5e0f4bdcb),
    UINT64_C(0x4db8b7e45147a72d),	UINT64_C(0x5f1f5b1ae9ae89d0),
    UINT64_C(0x9c33061a8d43cdf2),	UINT64_C(0x090d1c46191cf22c),
    UINT64_C(0x14a4db6d4f652805),	UINT64_C(0xad04b93d64ab96c3),
    UINT64_C(0x872dc535072184e5),	UINT64_C(0x76c01e6ec4ce7def),
    UINT64_C(0xe1b4022b96844bda),	UINT64_C(0x1aae6c5e205b7420),
    UINT64_C(0x81fe5ecee980cdba),	UINT64_C(0xe1f443ed1eced61b),
    UINT64_C(0xf0527b6acca1c7b3),	UINT64_C(0x4ca9a230e4df079b),
    UINT64_C(0x560c7d91d47a4ccb),	UINT64_C(0xee8e2bd0105ef29f),
    UINT64_C(0xf2a2f8ac0013baca),	UINT64_C(0x74b138f535cc596e),
    UINT64_C(0x1f5b4a69b0c52fca),	UINT64_C(0x70727a50b991647e),
    UINT64_C(0x1daac9340820db36),	UINT64_C(0x907722fe95348019),
    UINT64_C(0xbd12276eaff67f3f),	UINT64_C(0x820711f04c601de9),
    UINT64_C(0x11ae096f2259cbef),	UINT64_C(0x9470f5af8e8a5a49),
    UINT64_C(0xdf5f1ca6f7c2f8bd),	UINT64_C(0x0c6e20342dc09bae),
    UINT64_C(0xa396c9fce0e3d24a),	UINT64_C(0xd1f6d66a64132fee),
    UINT64_C(0x4d9b61ddbe66ca72),	UINT64_C(0xb4c2c447d8d4eabc),
    UINT64_C(0xb8a1fbd63745adbe),	UINT64_C(0x1b7830a702908e01),
    UINT64_C(0x32a77efa97dc85ee),	UINT64_C(0xaab406e0f671b806),
    UINT64_C(0xdf8eda17faca23b4),	UINT64_C(0xf15e63fca68ed3e7),
    UINT64_C(0x7df452b07843794f),	UINT64_C(0x61b01f8033fdc806),
    UINT64_C(0x6a3468375a771aed),	UINT64_C(0x01c8dd138da1667f),
    UINT64_C(0xd2f74e449164f79f),	UINT64_C(0x8e83478c0ac69a2f),
    UINT64_C(0xe27b1aeea8f30c89),	UINT64_C(0x20041db47f4894d5),
    UINT64_C(0x2fe03f112b5249e1),	UINT64_C(0x3c1d6f7fa4f2f2ff),
    UINT64_C(0x88509cb562e1ec69),	UINT64_C(0x63c8f47783e35d1b),
    UINT64_C(0xb925e3153c0adf3d),	UINT64_C(0x272f76c7e02bf5eb),
    UINT64_C(0xc534045dbec56f6d),	UINT64_C(0x5522e1314c2b6eb1),
    UINT64_C(0x203ba87728d47798),	UINT64_C(0x0e2193192e2aed5a),
    UINT64_C(0xd843cdaba59712ac),	UINT64_C(0x3433f095e81dbb87),
    UINT64_C(0x388394e366e9ad8b),	UINT64_C(0x184adb64bab7542b),
    UINT64_C(0x844285f65bc3c1dc),	UINT64_C(0x3716bf0818d35314),
    UINT64_C(0xe4e6984161be419f),	UINT64_C(0x69815296eff36c4c),
    UINT64_C(0x3848e21b9a2a4df9),	UINT64_C(0xd3029f0439556439),
    UINT64_C(0xc7ad5ff74a120fb9),	UINT64_C(0xb199d2f4b2fd59ce),
    UINT64_C(0xdc75f80743e6f7ba),	UINT64_C(0xf5d38ce7faab1b81),
    UINT64_C(0x7d75b9e69b1149bd),	UINT64_C(0x4783744e79c0d8de),
    UINT64_C(0x26740df8ef6f6bd3),	UINT64_C(0x8a7bf41a63c38b22),
    UINT64_C(0xb649f23511ab1c5a),	UINT64_C(0x619610930923b68f),
    UINT64_C(0x56bc08ca93e15af7),	UINT64_C(0x00e6eee4e2982ad0),
    UINT64_C(0xaca804c087ef0caf),	UINT64_C(0xce9b5227f8cd9ba3),
    UINT64_C(0xc882136f09587db5),	UINT64_C(0xecd4e6a1cb462a2f),
    UINT64_C(0x97e5679161db60cd),	UINT64_C(0xcb7f515a810bebd0),
    UINT64_C(0x5f6467a7b4e7fda3),	UINT64_C(0x1deefc057984cba1),
    UINT64_C(0x38aaf48a52215621),	UINT64_C(0x6913dedb57c126b2),
    UINT64_C(0x991b6e3b51051470),	UINT64_C(0xdf6d9a5be20d5310),
    UINT64_C(0x1beaab2e23043ebb),	UINT64_C(0xb8d8efd1b3aedcbd),
    UINT64_C(0xfbc2b3f680375728),	UINT64_C(0xcf2f9ae4f83d876c),
    UINT64_C(0xd27fbaaf4af0fea3),	UINT64_C(0xd81a9f62555a09a6),
    UINT64_C(0x5f9ee94fdf9e91c4),	UINT64_C(0x049d115622969aec),
    UINT64_C(0x97a1320bc1702004),	UINT64_C(0xa6ca38a8969f04dd),
    UINT64_C(0x24de942a7be6fa9a),	UINT64_C(0xf41ab00d0a5565ae),
    UINT64_C(0x930c4433b2bbc784),	UINT64_C(0x8ba018e2447cbad2),
    UINT64_C(0x366b6f8e812a5b02),	UINT64_C(0xe11103abd9aad94d),
    UINT64_C(0x40608339029a6b8f),	UINT64_C(0x1903098afab714b0),
    UINT64_C(0xb2fac1dc6d67c51c),	UINT64_C(0xb51263e52288bb9e),
    UINT64_C(0x8d4c665c26fc0af3),	UINT64_C(0xd43ce089d8355dc5),
    UINT64_C(0xdf3af6e733b0ae82),	UINT64_C(0x187ac21b65152973),
    UINT64_C(0xb3e21ef7979d56c7),	UINT64_C(0xed9d023adb39e7e6),
    UINT64_C(0x1b182f9961654c2a),	UINT64_C(0xc9b79331609b8ced),
    UINT64_C(0x84d493a6f46b5f0e),	UINT64_C(0xcd22ec297faad135),
    UINT64_C(0x384d2a837bee2775),	UINT64_C(0x89e3696d04ab2e6a),
    UINT64_C(0x84eac9a2d4f05716),	UINT64_C(0x7cd9081c601bb1fb),
    UINT64_C(0x3be77ac9654a9ae6),	UINT64_C(0xb2352010a9beee62),
    UINT64_C(0x05091ced308ce08c),	UINT64_C(0xe678c0c76d88bf99),
    UINT64_C(0xcb72636907494f35),	UINT64_C(0x6f9772e73a93e082),
    UINT64_C(0x787b08f1e5ec2a49),	UINT64_C(0x369e3f6a8ad6f95d),
    UINT64_C(0x9318db451ac52fcc),	UINT64_C(0xd1d583887d1fc803),
    UINT64_C(0x523e616de341c79a),	UINT64_C(0x4e69c322fbea1e49),
    UINT64_C(0x2b2f76a2893eeabb),	UINT64_C(0xa548e414c05d0f96),
    UINT64_C(0x1aad0480fab8b220),	UINT64_C(0x18d20b2ae56d0733),
    UINT64_C(0xdaed1af33b41596c),	UINT64_C(0x8774a5b9584c382c),
    UINT64_C(0x7015424674a46d5e),	UINT64_C(0x777312a1261066e5),
    UINT64_C(0x172d29da34fd0bdc),	UINT64_C(0x0a2cd64798b845c2),
    UINT64_C(0x1a2d248a55d3fe4c),	UINT64_C(0x93d81be3bdb3e22c),
    UINT64_C(0xa0be64ebd3a5e96c),	UINT64_C(0x9260d7079b0319ed),
    UINT64_C(0xa6dbc0c084fb9cf5),	UINT64_C(0x97b0da2edab3bfb9),
    UINT64_C(0x19d2c23600ae757a),	UINT64_C(0x0a0d84654aecbc97),
    UINT64_C(0x1dfa16397faac51c),	UINT64_C(0x501af5f31181df61),
    UINT64_C(0x8ccea8e25a24b37e),	UINT64_C(0xdcc8ea12fd587f71),
    UINT64_C(0xca01b99bf79bddb0),	UINT64_C(0xc724bf4fc9868aba),
    UINT64_C(0xf60d2e69d1c0bb36),	UINT64_C(0x6c62ec1be0425158),
    UINT64_C(0x3d79afebe8a686c1),	UINT64_C(0x35a733fa9ade165b),
    UINT64_C(0x456fe5b1c6a8e1ca),	UINT64_C(0x713b22d621839041),
    UINT64_C(0xd92f608099e82e90),	UINT64_C(0x3453eeacd8db39bd),
    UINT64_C(0x85d75154bb12e3d0),	UINT64_C(0x895f5c29b15f0b54),
    UINT64_C(0x0d2e6277d07bc2e2),	UINT64_C(0x2f3dec7b02b25d2b),
    UINT64_C(0x00ce21dba1b45bb2),	UINT64_C(0xa869e3e943aceb84),
    UINT64_C(0x5e6bb3c869a58c33),	UINT64_C(0x8dcc0e10596cc202),
    UINT64_C(0xfe4e9b4473c3decb),	UINT64_C(0xaa93a024052a0c30),
    UINT64_C(0x4a363355c5c6ef75),	UINT64_C(0x566a9927dc34cd32),
    UINT64_C(0x8580ff4a9b375f4c),	UINT64_C(0x7433fd4f07d1ac79),
    UINT64_C(0x1e8adf4450cca47d),	UINT64_C(0x5f942e3489601a66),
    UINT64_C(0x979e00930617f3e8),	UINT64_C(0x1c46d595f828263f),
    UINT64_C(0xa517a421aa900e0e),	UINT64_C(0xab9a0487348e7486),
    UINT64_C(0x51ab4391dfb46ffb),	UINT64_C(0x35b560ee4b56220d),
    UINT64_C(0xcb207f05a70a2792),	UINT64_C(0xc31b833b967062c7),
    UINT64_C(0x6d250d1760dfdab4),	UINT64_C(0x47fc6b6973b91f28),
    UINT64_C(0xc9352864cdbc7086),	UINT64_C(0xc14a23849ae3727b),
    UINT64_C(0x19d8fcc180b949c8),	UINT64_C(0xe4bee24982431d74),
    UINT64_C(0x8bc164fc10b1cc8c),	UINT64_C(0xd8dc2d6ebbb2fd0d),
    UINT64_C(0x03b954b129e0de87),	UINT64_C(0xc3d4327bcf15e685),
    UINT64_C(0xef166291c5909b9f),	UINT64_C(0x54aced56615fadeb),
    UINT64_C(0x1196ec1bee339d28),	UINT64_C(0x9adb7618dd03423e),
    UINT64_C(0x353171333b3f5d0f),	UINT64_C(0x6c2eadc0e8e18e6f),
    UINT64_C(0xb2d01b97ac62ea36),	UINT64_C(0x8dd3cf389c679444),
    UINT64_C(0x5ef2a358a2d0501a),	UINT64_C(0xf5f8a84c75bc92e6),
    UINT64_C(0xc84ee02cc0460feb),	UINT64_C(0xbcee6ebac8e14208),
    UINT64_C(0x4877fe3cfd59e687),	UINT64_C(0x0b6f2892e72b7b0f),
    UINT64_C(0xfd594593e717ce75),	UINT64_C(0xc741b48073efa883),
    UINT64_C(0x57a3333b30c30793),	UINT64_C(0xb4812bc4f43f5272),
    UINT64_C(0xe053d49e89a9b6c5),	UINT64_C(0xa86e915191acf997),
    UINT64_C(0x3c1c1d38c7c31327),	UINT64_C(0x20765164fbd43001),
    UINT64_C(0x999c438408be25d1),	UINT64_C(0xb7d6172859b6c2e9),
    UINT64_C(0x7a77c222207d3258),	UINT64_C(0x55d5f42fcdc07145),
    UINT64_C(0x20dab98ebd99352c),	UINT64_C(0x57755b29f6f38bf3),
    UINT64_C(0x6312784ab9e60ce5),	UINT64_C(0x93fe084ab6f20aab),
    UINT64_C(0x2f571ed305e1f05a),	UINT64_C(0x16fa39d470815fca),
    UINT64_C(0xa7515f4f2c2c9484),	UINT64_C(0x5d4f72489f2f2a90),
    UINT64_C(0x295f0363001120ea),	UINT64_C(0x616b63186b372eb8),
    UINT64_C(0xc922b277f974bf1e),	UINT64_C(0xac8092534802b0c3),
    UINT64_C(0xac4e944935543e54),	UINT64_C(0x138d811d868aebc6),
    UINT64_C(0x65140fe2e66af9ea),	UINT64_C(0xa330b55b1fd9db0a),
    UINT64_C(0x7bd77ec44d2d7c8b),	UINT64_C(0xd27c2ab06ceb6d5d),
    UINT64_C(0xab539d0ea440d896),	UINT64_C(0x63378505cbd389f0),
    UINT64_C(0xd45afa02530ebc99),	UINT64_C(0x24cb49e2a02c0ebd),
    UINT64_C(0xb7802ff1ac41d774),	UINT64_C(0xb1263f8844d7fef3),
    UINT64_C(0x6a49bc5664cf4598),	UINT64_C(0x14c2cc671633d6bb),
    UINT64_C(0x48c2168fb3705fef),	UINT64_C(0x130b5b107ced43c8),
    UINT64_C(0xce881b282089840f),	UINT64_C(0xf6171c551a743d6e),
    UINT64_C(0xc4ebe769d7c41946),	UINT64_C(0xd50983339f19d7fe),
    UINT64_C(0x29b76cd4cb52c07b),	UINT64_C(0x6f3e06eab4b5c762),
    UINT64_C(0x7122f50ff020ab29),	UINT64_C(0x0445ddec3c165432),
    UINT64_C(0xfc92d82190e725ab),	UINT64_C(0x54c0912bc210cdb3),
    UINT64_C(0x95e14059ef49f81a),	UINT64_C(0xd7e428d390076bc0),
    UINT64_C(0xdc34b0f261873fd1),	UINT64_C(0x7ca4fc4c1e6580da),
    UINT64_C(0xf37cb1d511bbed3c),	UINT64_C(0x817ec23ae72b88a2),
    UINT64_C(0xcaaedbe0cee7813e),	UINT64_C(0x81a2abf25925b81d),
    UINT64_C(0xa134f5eb478ba4c2),	UINT64_C(0x8892b54a20cccb37),
    UINT64_C(0x326e1e8101d5dd24),	UINT64_C(0xfd686961443df410),
    UINT64_C(0xbbee902dc695874e),	UINT64_C(0x7f6fc00fb3b4c229),
    UINT64_C(0xa95a8f78d406c957),	UINT64_C(0xec74605128f95ae0),
    UINT64_C(0xaee92d9cf78ec402),	UINT64_C(0x20001fd4c36d2ae8),
    UINT64_C(0x0be78d37c3350041),	UINT64_C(0xb3c9ea320c595e26),
};

static uint64_t const 
short_expected_values[] = {
    UINT64_C(0xaf71879ecd0e427c),	UINT64_C(0xc6d16297d0ff424c),
    UINT64_C(0x0480f91e5d2a621c),	UINT64_C(0xc88b4469bb5394e2),
    UINT64_C(0x06f81e4b71d10720),	UINT64_C(0xb46b0f5e8c3678b9),
    UINT64_C(0x844d2e1c67a1f6fb),	UINT64_C(0x707c24712d323c3f),
    UINT64_C(0x0342eaf490a941cd),	UINT64_C(0x94d5f526482449a2),
    UINT64_C(0xe6b309e969d38243),	UINT64_C(0xaeb52285b9a9f902),
    UINT64_C(0x38e4790994ee22ec),	UINT64_C(0x7ee264924daa7c9c),
    UINT64_C(0xcc563e9b9c8772e4),	UINT64_C(0xada776d405d49bf5),
    UINT64_C(0xfcc0d33f7ded5a27),	UINT64_C(0x874ddb13e6de19bb),
    UINT64_C(0x6e3dd468a6d77ead),	UINT64_C(0x325aca6e0e4e98fb),
    UINT64_C(0xd716e672c63fc2be),	UINT64_C(0x604a7174016ec5d6),
    UINT64_C(0x01175f1d59f00379),	UINT64_C(0x60b831226e93b8f9),
    UINT64_C(0x0caea54676c78dfb),	UINT64_C(0x69bc3db6e39af208),
    UINT64_C(0x3ef0191d67bd7355),	UINT64_C(0x2f3ee224f7245027),
    UINT64_C(0x5a2a184eb1012ffe),	UINT64_C(0xa851903721c43b54),
    UINT64_C(0x9752dab1a1c763a8),	UINT64_C(0xbfca09900e5d4e70),
    UINT64_C(0x44cdbaf412b7ea5f),	UINT64_C(0x21ea9cbab2679984),
    UINT64_C(0x1dc0738f07541757),	UINT64_C(0x31d390f786f13fe7),
    UINT64_C(0x6b8cf17b3c9e9cfe),	UINT64_C(0x6bfc26690ee1317c),
    UINT64_C(0x5d53e831d6d55805),	UINT64_C(0x13330f5d109972e3),
    UINT64_C(0x41a69128f03d8269),	UINT64_C(0x586fcac7696a325a),
    UINT64_C(0x21928866bc534003),	UINT64_C(0xe69442f79329cbcb),
    UINT64_C(0x05d19624554965d9),	UINT64_C(0x14333e0ee52ee240),
    UINT64_C(0xd95be6a7fe943424),	UINT64_C(0x56c50eb0768a5ecb),
    UINT64_C(0x35229db80365400c),	UINT64_C(0xb6d5ef025c21866e),
    UINT64_C(0xf94746beafa5e291),	UINT64_C(0x6ed50cf242463d0d),
    UINT64_C(0x05a8542db37dc607),	UINT64_C(0x6e732b8d1e771e2b),
    UINT64_C(0xc3d5da3c44fac901),	UINT64_C(0x2a55035c54e0ca3d),
    UINT64_C(0xc570d716b149f0f7),	UINT64_C(0x36723ba881e1f17e),
    UINT64_C(0x8759095758e7a17a),	UINT64_C(0x203282c82d12c0f2),
    UINT64_C(0xc50a3ad1d16646e8),	UINT64_C(0x8ef12cdac0cdb749),
    UINT64_C(0x45b3df78018f398b),	UINT64_C(0x31567320c9ff9521),
};

static void
piecemeal_hash(void const*p_msg, size_t p_len, uint64_t *ph1, uint64_t *ph2)
{
    spooky_context_t ctxt;

    uint64_t seed0 = *ph1;
    uint64_t seed1 = *ph2;
    spooky_init(&ctxt, seed0, seed1);
    uint32_t rng = 0xdeadbeef;

    int const mod_amt = (p_len < SC_BUFSIZE) ? 32 : SC_BUFSIZE;

    uint8_t const *lmsg = p_msg;
    while (p_len > 0) {
        int hlen = xorshift32(&rng) % mod_amt;
        if (hlen > p_len) {
            hlen = p_len;
        }
        spooky_update(&ctxt, lmsg, hlen);
        lmsg += hlen;
        p_len -= hlen;
    }

    spooky_final(&ctxt, ph1, ph2);
}

int
main(void)
{
    printf("STARTING TEST!!\n");

    uint8_t *buffer = malloc(DATASIZE);
    randfill(buffer, DATASIZE, 0); // Use the default random seed

    uint8_t *hashbuf = malloc(DATASIZE + SC_BUFSIZE);

    uint64_t seed1;
    uint64_t seed2;

    // For every value between 0 and SC_BUFSIZE, shift the buffer by that many
    // bytes and hash it
    for (int i = 0; i < SC_BUFSIZE; ++i) {

        // For every value between 0 and SC_BUFSIZE, subtract that many bytes
        // from the data len and hash the data.
        for (int j = 0; j < SC_BUFSIZE; ++j) {
            memset(hashbuf, 0, DATASIZE + SC_BUFSIZE);
            memcpy(hashbuf + i, buffer, DATASIZE - j);
            seed1 = 123456789;
            seed2 = 987654321;
            spooky_hash128(hashbuf + i, DATASIZE - j, &seed1, &seed2);

            // Compare it to our precalculated values
            uint64_t const expseed1 = expected_values[2*j];
            uint64_t const expseed2 = expected_values[2*j+1];
            if ((seed1 != expseed1) || (seed2 != expseed2)) {
                printf("TEST FAILED WITH UNALIGNMENT %d AND NUMBYTES %d!\n", i, DATASIZE - j);
                abort();
            }
        }
    }

    // Do the same but use the small data hasher
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 32; ++j) {
            memset(hashbuf, 0, DATASIZE + SC_BUFSIZE);
            memcpy(hashbuf + i, buffer, SC_BUFSIZE - j);
            seed1 = 123456789;
            seed2 = 987654321;
            spooky_hash128(hashbuf + i, DATASIZE - j, &seed1, &seed2);
            // Compare it to our precalculated values
            uint64_t const expseed1 = short_expected_values[2*j];
            uint64_t const expseed2 = short_expected_values[2*j+1];
            if ((seed1 != expseed1) || (seed2 != expseed2)) {
                printf("TEST FAILED WITH UNALIGNMENT %d AND NUMBYTES %d!\n", i, SC_BUFSIZE - j);
                abort();
            }
        }
    }
    
    // For every value between 0 and SC_BUFSIZE, shift the buffer by that many
    // bytes and hash it
    for (int i = 0; i < SC_BUFSIZE; ++i) {

        // For every value between 0 and SC_BUFSIZE, subtract that many bytes
        // from the data len and hash the data.
        for (int j = 0; j < SC_BUFSIZE; ++j) {
            memset(hashbuf, 0, DATASIZE + SC_BUFSIZE);
            memcpy(hashbuf + i, buffer, DATASIZE - j);
            seed1 = 123456789;
            seed2 = 987654321;
            piecemeal_hash(hashbuf + i, DATASIZE - j, &seed1, &seed2);

            // Compare it to our precalculated values
            uint64_t const expseed1 = expected_values[2*j];
            uint64_t const expseed2 = expected_values[2*j+1];
            if ((seed1 != expseed1) || (seed2 != expseed2)) {
                printf("TEST FAILED WITH UNALIGNMENT %d AND NUMBYTES %d!\n", i, DATASIZE - j);
                abort();
            }
        }
    }

    // Do the same but use the small data hasher
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 32; ++j) {
            memset(hashbuf, 0, DATASIZE + SC_BUFSIZE);
            memcpy(hashbuf + i, buffer, SC_BUFSIZE - j);
            seed1 = 123456789;
            seed2 = 987654321;
            piecemeal_hash(hashbuf + i, DATASIZE - j, &seed1, &seed2);
            // Compare it to our precalculated values
            uint64_t const expseed1 = short_expected_values[2*j];
            uint64_t const expseed2 = short_expected_values[2*j+1];
            if ((seed1 != expseed1) || (seed2 != expseed2)) {
                printf("TEST FAILED WITH UNALIGNMENT %d AND NUMBYTES %d!\n", i, SC_BUFSIZE - j);
                abort();
            }
        }
    }

    free(buffer);
    free(hashbuf);

    printf("TEST PASSED!\n");
}
