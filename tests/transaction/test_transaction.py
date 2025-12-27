"""
Copyright 2025 Biglup Labs.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import pytest
from cometa import (
    CardanoError,
    CborReader,
    CborWriter,
    Transaction,
    TransactionBody,
    TransactionInput,
    TransactionInputSet,
    TransactionOutput,
    TransactionOutputList,
    WitnessSet,
    VkeyWitnessSet,
    AuxiliaryData,
    Address,
    JsonWriter,
    JsonFormat,
)

CBOR = "84af00d90102818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5000181a2005839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc01820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e020a031903e804d90102828304581c26b17b78de4f035dc0bfce60d1d3c3a8085c38dcce5fb8767e518bed1901f48405581c0d94e174732ef9aae73f395ab44507bfa983d65023c11a951f0c32e4581ca646474b8f5431261506b6c273d307c7569a4eb6c96b42dd4a29520a582003170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c11131405a1581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d0050758202ceb364d93225b4a0f004a0975a13eb50c3cc6348474b4fe9121f8dc72ca0cfa08186409a3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c413831581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e0b58206199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de0dd90102818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5010ed9010281581c6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d3910a2005839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc01820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e11186412d90102818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500a700d90102818258206199186adb51974690d7247d2646097d2c62763b767b528816fb7ed3f9f55d395840bdea87fca1b4b4df8a9b8fb4183c0fab2f8261eb6c5e4bc42c800bb9c8918755bdea87fca1b4b4df8a9b8fb4183c0fab2f8261eb6c5e4bc42c800bb9c891875501d90102868205186482041901f48200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f548201818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f548202818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f54830301818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f5402d9010281845820deeb8f82f2af5836ebbc1b450b6dbf0b03c93afe5696f10d49e8a8304ebfac01584064676273786767746f6768646a7074657476746b636f6376796669647171676775726a687268716169697370717275656c6876797071786565777072796676775820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45041a003d90102815820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b45004d9010281187b05a282010082d87a9f187bff82190bb8191b5882020182d87a9f187bff821913881907d006d90102815820b6dbf0b03c93afe5696f10d49e8a8304ebfac01deeb8f82f2af5836ebbc1b450f5d90103a100a6011904d20263737472039f1904d263737472ff0445627974657305a2667374726b6579187b9f676c6973746b6579ff6873747276616c75650626"
CBOR2 = "84a600d9010281825820260aed6e7a24044b1254a87a509468a649f522a4e54e830ac10f27ea7b5ec61f010183a300581d70b429738bd6cc58b5c7932d001aa2bd05cfea47020a556c8c753d4436011a004c4b40028200582007845f8f3841996e3d8157954e2f5e2fb90465f27112fc5fe9056d916fae245ba200583900b1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339ba011a04636769a200583900b1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339ba01821a00177a6ea2581c648823ffdad1610b4162f4dbc87bd47f6f9cf45d772ddef661eff198a5447742544319271044774554481a0031f9194577444f47451a0056898d4577555344431a000fc589467753484942411a000103c2581c659ab0b5658687c2e74cd10dba8244015b713bf503b90557769d77a7a14a57696e675269646572731a02269552021a0002e665031a01353f84081a013531740b58204107eada931c72a600a6e3305bd22c7aeb9ada7c3f6823b155f4db85de36a69aa200d9010281825820e686ade5bc97372f271fd2abc06cfd96c24b3d9170f9459de1d8e3dd8fd385575840653324a9dddad004f05a8ac99fa2d1811af5f00543591407fb5206cfe9ac91bb1412404323fa517e0e189684cd3592e7f74862e3f16afbc262519abec958180c04d9010281d8799fd8799fd8799fd8799f581cb1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c68ffd8799fd8799fd8799f581c042f1946335c498d2e7556c5c647c4649c6a69d2b645cd1428a339baffffffff581cb1814238b0d287a8a46ce7348c6ad79ab8995b0e6d46010e2d9e1c681b000001863784a12ed8799fd8799f4040ffd8799f581c648823ffdad1610b4162f4dbc87bd47f6f9cf45d772ddef661eff1984577444f4745ffffffd8799fd87980190c8efffff5f6"
CBOR3 = "84a40081825820f6dd880fb30480aa43117c73bfd09442ba30de5644c3ec1a91d9232fbe715aab000182a20058390071213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2cad9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13011b0000000253c8e4f6a300581d702ed2631dbb277c84334453c5c437b86325d371f0835a28b910a91a6e011a001e848002820058209d7fee57d1dbb9b000b2a133256af0f2c83ffe638df523b2d1c13d405356d8ae021a0002fb050b582088e4779d217d10398a705530f9fb2af53ffac20aef6e75e85c26e93a00877556a10481d8799fd8799f40ffd8799fa1d8799fd8799fd87980d8799fd8799f581c71213dc119131f48f54d62e339053388d9d84faedecba9d8722ad2caffd8799fd8799fd8799f581cd9debf34071615fc6452dfc743a4963f6bec68e488001c7384942c13ffffffffffd8799f4040ffff1a001e8480a0a000ffd87c9f9fd8799fd8799fd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffd8799f4040ffd87a9f1a00989680ffffd87c9f9fd8799fd87a9fd8799f4752656c65617365d8799fd87980d8799fd8799f581caa47de0ab3b7f0b1d8d196406b6af1b0d88cd46168c49ca0557b4f70ffd8799fd8799fd8799f581cd4b8fc88aec1d1c2f43ca5587898d88da20ef73964b8cf6f8f08ddfbffffffffffff9fd8799f0101ffffffd87c9f9fd8799fd87b9fd9050280ffd87980ffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980ffffff1b000001884e1fb1c0d87980fffff5f6"
CBOR_NULLIFY_ENTROPY = "83a50081825820bf30608a974d09c56dd62ca10199ec11746ea2d90dbd83649d4f37c629b1ba840001818258390117d237fb8f952c995cd28f73c555adc2307322d819b7f565196ce754348144bff68f23c1386b85dea0f8425ca574b1a11e188ffaba67537c1a0048f96f021a000351d1031a019732f30682a7581c162f94554ac8c225383a2248c245659eda870eaa82d0ef25fc7dcd82a10d8100581c2075a095b3c844a29c24317a94a643ab8e22d54a3a3a72a420260af6a10d8100581c268cfc0b89e910ead22e0ade91493d8212f53f3e2164b2e4bef0819ba10d8100581c60baee25cbc90047e83fd01e1e57dc0b06d3d0cb150d0ab40bbfead1a10d8100581cad5463153dc3d24b9ff133e46136028bdc1edbb897f5a7cf1b37950ca10d8100581cb9547b8a57656539a8d9bc42c008e38d9c8bd9c8adbb1e73ad529497a10d8100581cf7b341c14cd58fca4195a9b278cce1ef402dc0e06deb77e543cd1757a10d8100190103a1008882582061261a95b7613ee6bf2067dad77b70349729b0c50d57bc1cf30de0db4a1e73a858407d72721e7504e12d50204f7d9e9d9fe60d9c6a4fd18ad629604729df4f7f3867199b62885623fab68a02863e7877955ca4a56c867157a559722b7b350b668a0b8258209180d818e69cd997e34663c418a648c076f2e19cd4194e486e159d8580bc6cda5840af668e57c98f0c3d9b47c66eb9271213c39b4ea1b4d543b0892f03985edcef4216d1f98f7b731eedc260a2154124b5cab015bfeaf694d58966d124ad2ff60f0382582089c29f8c4af27b7accbe589747820134ebbaa1caf3ce949270a3d0c7dcfd541b58401ad69342385ba6c3bef937a79456d7280c0d539128072db15db120b1579c46ba95d18c1fa073d7dbffb4d975b1e02ebb7372936940cff0a96fce950616d2f504825820f14f712dc600d793052d4842d50cefa4e65884ea6cf83707079eb8ce302efc855840638f7410929e7eab565b1451effdfbeea2a8839f7cfcc4c4483c4931d489547a2e94b73e4b15f8494de7f42ea31e573c459a9a7e5269af17b0978e70567de80e8258208b53207629f9a30e4b2015044f337c01735abe67243c19470c9dae8c7b73279858400c4ed03254c33a19256b7a3859079a9b75215cad83871a9b74eb51d8bcab52911c37ea5c43bdd212d006d1e6670220ff1d03714addf94f490e482edacbb08f068258205fddeedade2714d6db2f9e1104743d2d8d818ecddc306e176108db14caadd4415840bf48f5dd577b5cb920bfe60e13c8b1b889366c23e2f2e28d51814ed23def3a0ff4a1964f806829d40180d83b5230728409c1f18ddb5a61c44e614b823bd43f01825820cbc6b506e94fbefe442eecee376f3b3ebaf89415ef5cd2efb666e06ddae48393584089bff8f81a20b22f2c3f8a2288b15f1798b51f3363e0437a46c0a2e4e283b7c1018eba0b2b192d6d522ac8df2f2e95b4c8941b387cda89857ab0ae77db14780c825820e8c03a03c0b2ddbea4195caf39f41e669f7d251ecf221fbb2f275c0a5d7e05d158402643ac53dd4da4f6e80fb192b2bf7d1dd9a333bbacea8f07531ba450dd8fb93e481589d370a6ef33a97e03b2f5816e4b2c6a8abf606a859108ba6f416e530d07f6"

TX_BODY_CBOR = "b100818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5000181825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e020a031903e804828304581c26b17b78de4f035dc0bfce60d1d3c3a8085c38dcce5fb8767e518bed1901f48405581c0d94e174732ef9aae73f395ab44507bfa983d65023c11a951f0c32e4581ca646474b8f5431261506b6c273d307c7569a4eb6c96b42dd4a29520a582003170a2e7597b7b7e3d84c05391d139a62b157e78786d8c082f29dcf4c11131405a2581de013cf55d175ea848b87deb3e914febd7e028e2bf6534475d52fb9c3d005581de0404b5a4088ae9abcf486a7e7b8f82069e6fcfe1bf226f1851ce72570030682a3581c00000000000000000000000000000000000000000000000000000001b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a10098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000002b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a10098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba581c00000000000000000000000000000000000000000000000000000003b60018640118c80219012c03190190041901f4051a001e8480061a0bebc200071903200819038409d81e8201020ad81e8201030bd81e8201040cd81e8201050d8201582000000000000000000000000000000000000000000000000000000000000000000e820103101903e8111988b812a10098a61a0003236119032c01011903e819023b00011903e8195e7104011903e818201a0001ca761928eb041959d818641959d818641959d818641959d818641959d818641959d81864186418641959d81864194c5118201a0002acfa182019b551041a000363151901ff00011a00015c3518201a000797751936f404021a0002ff941a0006ea7818dc0001011903e8196ff604021a0003bd081a00034ec5183e011a00102e0f19312a011a00032e801901a5011a0002da781903e819cf06011a00013a34182019a8f118201903e818201a00013aac0119e143041903e80a1a00030219189c011a00030219189c011a0003207c1901d9011a000330001901ff0119ccf3182019fd40182019ffd5182019581e18201940b318201a00012adf18201a0002ff941a0006ea7818dc0001011a00010f92192da7000119eabb18201a0002ff941a0006ea7818dc0001011a0002ff941a0006ea7818dc0001011a000c504e197712041a001d6af61a0001425b041a00040c660004001a00014fab18201a0003236119032c010119a0de18201a00033d7618201979f41820197fb8182019a95d1820197df718201995aa18201a0374f693194a1f0a1382d81e820102d81e82010214821b00000001000000001b000000010000000015821b00000001000000001b0000000100000000161903ba19020b0758202ceb364d93225b4a0f004a0975a13eb50c3cc6348474b4fe9121f8dc72ca0cfa08186409a3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c413831581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e0b58206199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d38abc123de0d818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d5010e81581c6199186adb51974690d7247d2646097d2c62763b16fb7ed3f9f55d390f0110825839009493315cd92eb5d8c4304e67b7e16ae36d61d34502694657811a2c8e32c728d3861e164cab28cb8f006448139c8f1740ffb8e7aa9e5232dc820aa3581c2a286ad895d091f2b3d168a6091ad2627d30a72761a5bc36eef00740a14014581c659f2917fb63f12b33667463ee575eeac1845bbc736b9c0bbc40ba82a14454534c411832581c7eae28af2208be856f7a119668ae52a49b73725e326dc16579dcc373a240182846504154415445181e11186412818258200f3abbc8fc19c2e61bab6059bf8a466e6e754833a08a62a6c56fe0e78f19d9d500"
AUXILIARY_DATA_CBOR = "d90103a500a11902d5a4187b1904d2636b65796576616c7565646b65793246000102030405a1190237656569676874a119029a6463616b6501848204038205098202818200581c3542acb3a64d80c29302260d62c3b87a742ad14abf855ebc6733081e830300818200581cb5ae663aaea8e500157bdf4baafd6f5ba0ce5759f7cd4101fc132f5402844746010000220010474601000022001147460100002200124746010000220013038447460100002200104746010000220011474601000022001247460100002200130483474601000022001047460100002200114746010000220012"
WITNESS_SET_CBOR = "a100838258204a352f53eb4311d552aa9e1c6f0125846a3b607011d691f0e774d893d940b8525840c4f13cc397a50193061ce899b3eda906ad1adf3f3d515b52248ea5aa142781cd9c2ccc52ac62b2e1b5226de890104ec530bda4c38a19b691946da9addb3213f5825820290c08454c58a8c7fad6351e65a652460bd4f80f485f1ccfc350ff6a4d5bd4de5840026f47bab2f24da9690746bdb0e55d53a5eef45a969e3dd2873a3e6bb8ef3316d9f80489bacfd2f543108e284a40847ae7ce33fa358fcfe439a37990ad3107e98258204d953d6a9d556da3f3e26622c725923130f5733d1a3c4013ef8c34d15a070fd75840f9218e5a569c5ace38b1bb81e1f1c0b2d7fea2fe7fb913fdd06d79906436103345347a81494b83f83bf43466b0cebdbbdcef15384f67c255e826c249336ce2c7"

CBOR_TX_ID = "c7f20e9550b5631f07622a583a5103f19bcfa28eee89f39fff0eb24c2ad74619"
CBOR3_TX_ID = "2d7f290c815e061fb7c27e91d2a898bd7b454a71c9b7a26660e2257ac31ebe32"
CBOR_NULLIFY_ENTROPY_TX_ID = "fc863a441b55acceebb7d25c81ff7259e4fc9b92fbdf6d594118fb8f1110a78c"

VKEY_WITNESS_CBOR = "d90102848258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a8258203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c58406291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"

TX_ID_HASH = "0102030405060708090a0b0c0d0e0f0e0d0c0b0a090807060504030201001020"
ADDRESS_BECH32 = (
    "addr_test1qpfhhfy2qgls50r9u4yh0l7z67xpg0a5rrhkmvzcuqrd0znuzcjqw982pcftgx53fu5527z2cj2tkx2h8ux2vxsg475q9gw0lz"
)


class TestTransactionNew:
    """Tests for Transaction.new() factory method."""

    def test_can_create_new_instance(self):
        """Test creating a new transaction with all components."""
        body = TransactionBody.from_cbor(CborReader.from_hex(TX_BODY_CBOR))
        witness_set = WitnessSet.from_cbor(CborReader.from_hex(WITNESS_SET_CBOR))
        auxiliary_data = AuxiliaryData.from_cbor(
            CborReader.from_hex(AUXILIARY_DATA_CBOR)
        )

        transaction = Transaction.new(body, witness_set, auxiliary_data)

        assert transaction is not None

    def test_can_create_with_none_auxiliary_data(self):
        """Test creating a transaction without auxiliary data."""
        body = TransactionBody.from_cbor(CborReader.from_hex(TX_BODY_CBOR))
        witness_set = WitnessSet.from_cbor(CborReader.from_hex(WITNESS_SET_CBOR))

        transaction = Transaction.new(body, witness_set, None)

        assert transaction is not None
        assert transaction.auxiliary_data is None

    def test_returns_error_if_body_is_none(self):
        """Test that creating without body raises error."""
        witness_set = WitnessSet.from_cbor(CborReader.from_hex(WITNESS_SET_CBOR))

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Transaction.new(None, witness_set, None)

    def test_returns_error_if_witness_set_is_none(self):
        """Test that creating without witness set raises error."""
        body = TransactionBody.from_cbor(CborReader.from_hex(TX_BODY_CBOR))

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            Transaction.new(body, None, None)

    def test_can_create_simple_transaction(self):
        """Test creating a simple transaction with basic components."""
        input_set = TransactionInputSet()
        tx_input = TransactionInput.from_hex(TX_ID_HASH, 0)
        input_set.add(tx_input)

        output_list = TransactionOutputList()
        address = Address.from_string(ADDRESS_BECH32)
        output = TransactionOutput.new(address, 1000000)
        output_list.add(output)

        body = TransactionBody.new(input_set, output_list, 200000)
        witness_set = WitnessSet()

        tx = Transaction.new(body, witness_set)

        assert tx is not None
        assert tx.body is not None
        assert tx.witness_set is not None


class TestTransactionFromCbor:
    """Tests for Transaction.from_cbor() deserialization."""

    def test_can_deserialize_from_cbor(self):
        """Test deserializing transaction from CBOR."""
        reader = CborReader.from_hex(CBOR)
        transaction = Transaction.from_cbor(reader)

        assert transaction is not None

    def test_can_deserialize_cbor2(self):
        """Test deserializing alternative transaction format."""
        reader = CborReader.from_hex(CBOR2)
        transaction = Transaction.from_cbor(reader)

        assert transaction is not None

    def test_can_deserialize_cbor3(self):
        """Test deserializing third transaction format."""
        reader = CborReader.from_hex(CBOR3)
        transaction = Transaction.from_cbor(reader)

        assert transaction is not None

    def test_can_deserialize_cbor_nullify_entropy(self):
        """Test deserializing transaction with nullified entropy."""
        reader = CborReader.from_hex(CBOR_NULLIFY_ENTROPY)
        transaction = Transaction.from_cbor(reader)

        assert transaction is not None

    def test_returns_error_if_not_array(self):
        """Test that invalid CBOR raises error."""
        reader = CborReader.from_hex("01")

        with pytest.raises(CardanoError):
            Transaction.from_cbor(reader)

    def test_returns_error_if_invalid_body(self):
        """Test that invalid transaction body raises error."""
        reader = CborReader.from_hex("84ef")

        with pytest.raises(CardanoError):
            Transaction.from_cbor(reader)


class TestTransactionToCbor:
    """Tests for Transaction.to_cbor() serialization."""

    def test_can_serialize_from_cache(self):
        """Test serializing transaction using cached CBOR."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        writer = CborWriter()

        transaction.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR

    def test_can_serialize_after_clear_cache(self):
        """Test serializing after clearing CBOR cache."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        transaction.clear_cbor_cache()
        writer = CborWriter()

        transaction.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR

    def test_can_serialize_cbor2(self):
        """Test serializing alternative transaction format."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR2))
        transaction.clear_cbor_cache()
        writer = CborWriter()

        transaction.to_cbor(writer)
        result = writer.to_hex()

        assert result == CBOR2

    def test_serialize_to_cbor_method(self):
        """Test the convenience serialize_to_cbor method."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        result = transaction.serialize_to_cbor()

        assert result == CBOR


class TestTransactionId:
    """Tests for Transaction.id property."""

    def test_can_get_transaction_id(self):
        """Test getting transaction ID from CBOR."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        tx_id = transaction.id

        assert tx_id.to_hex() == CBOR_TX_ID

    def test_can_get_transaction_id_cbor3(self):
        """Test getting transaction ID from CBOR3."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR3))

        tx_id = transaction.id

        assert tx_id.to_hex() == CBOR3_TX_ID

    def test_can_get_transaction_id_nullify_entropy(self):
        """Test getting transaction ID from nullified entropy transaction."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR_NULLIFY_ENTROPY))

        tx_id = transaction.id

        assert tx_id.to_hex() == CBOR_NULLIFY_ENTROPY_TX_ID

    def test_transaction_id_is_32_bytes(self):
        """Test that transaction ID is always 32 bytes."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        tx_id = transaction.id

        assert len(tx_id) == 32


class TestTransactionBody:
    """Tests for Transaction.body property."""

    def test_can_get_body(self):
        """Test getting transaction body."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        body = TransactionBody.from_cbor(CborReader.from_hex(TX_BODY_CBOR))

        transaction.body = body
        result = transaction.body

        assert result is not None

    def test_can_set_body(self):
        """Test setting transaction body."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        body = TransactionBody.from_cbor(CborReader.from_hex(TX_BODY_CBOR))

        transaction.body = body

        assert transaction.body is not None

    def test_set_body_with_none_raises_error(self):
        """Test that setting None body raises error."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            transaction.body = None


class TestTransactionWitnessSet:
    """Tests for Transaction.witness_set property."""

    def test_can_get_witness_set(self):
        """Test getting witness set."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        witness_set = WitnessSet.from_cbor(CborReader.from_hex(WITNESS_SET_CBOR))

        transaction.witness_set = witness_set
        result = transaction.witness_set

        assert result is not None

    def test_can_set_witness_set(self):
        """Test setting witness set."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        witness_set = WitnessSet.from_cbor(CborReader.from_hex(WITNESS_SET_CBOR))

        transaction.witness_set = witness_set

        assert transaction.witness_set is not None

    def test_set_witness_set_with_none_raises_error(self):
        """Test that setting None witness set raises error."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        with pytest.raises((CardanoError, TypeError, AttributeError)):
            transaction.witness_set = None


class TestTransactionAuxiliaryData:
    """Tests for Transaction.auxiliary_data property."""

    def test_can_get_auxiliary_data(self):
        """Test getting auxiliary data."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        auxiliary_data = AuxiliaryData.from_cbor(
            CborReader.from_hex(AUXILIARY_DATA_CBOR)
        )

        transaction.auxiliary_data = auxiliary_data
        result = transaction.auxiliary_data

        assert result is not None

    def test_can_set_auxiliary_data(self):
        """Test setting auxiliary data."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        auxiliary_data = AuxiliaryData.from_cbor(
            CborReader.from_hex(AUXILIARY_DATA_CBOR)
        )

        transaction.auxiliary_data = auxiliary_data

        assert transaction.auxiliary_data is not None

    def test_can_set_auxiliary_data_to_none(self):
        """Test setting auxiliary data to None."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        transaction.auxiliary_data = None

        assert transaction.auxiliary_data is None


class TestTransactionIsValid:
    """Tests for Transaction.is_valid property."""

    def test_can_set_is_valid_true(self):
        """Test setting is_valid to True."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        transaction.is_valid = True

        assert transaction.is_valid is True

    def test_can_set_is_valid_false(self):
        """Test setting is_valid to False."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        transaction.is_valid = False

        assert transaction.is_valid is False

    def test_can_get_is_valid(self):
        """Test getting is_valid after setting."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        transaction.is_valid = True
        result = transaction.is_valid

        assert result is True

    def test_is_valid_is_boolean(self):
        """Test that is_valid returns boolean."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        result = transaction.is_valid

        assert isinstance(result, bool)


class TestTransactionHasScriptData:
    """Tests for Transaction.has_script_data() method."""

    def test_returns_true_if_has_script_data(self):
        """Test transaction with script data returns True."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        result = transaction.has_script_data()

        assert result is True

    def test_returns_false_if_no_script_data(self):
        """Test transaction without script data returns False."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR_NULLIFY_ENTROPY))

        result = transaction.has_script_data()

        assert result is False


class TestTransactionClearCborCache:
    """Tests for Transaction.clear_cbor_cache() method."""

    def test_clear_cbor_cache_works(self):
        """Test clearing CBOR cache."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        transaction.clear_cbor_cache()
        writer = CborWriter()
        transaction.to_cbor(writer)

        assert writer.to_hex() == CBOR


class TestTransactionApplyVkeyWitnesses:
    """Tests for Transaction.apply_vkey_witnesses() method."""

    def test_can_apply_vkey_witnesses(self):
        """Test applying vkey witnesses to transaction."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        witness_set = WitnessSet.from_cbor(CborReader.from_hex(WITNESS_SET_CBOR))
        vkey_witness_set = VkeyWitnessSet.from_cbor(
            CborReader.from_hex(VKEY_WITNESS_CBOR)
        )

        transaction.witness_set = witness_set
        transaction.apply_vkey_witnesses(vkey_witness_set)

        assert transaction.witness_set is not None

    def test_can_apply_vkey_witnesses_to_empty_witness_set(self):
        """Test applying vkey witnesses to transaction with empty witness set."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        witness_set = WitnessSet()
        vkey_witness_set = VkeyWitnessSet.from_cbor(
            CborReader.from_hex(VKEY_WITNESS_CBOR)
        )

        transaction.witness_set = witness_set
        transaction.apply_vkey_witnesses(vkey_witness_set)

        assert transaction.witness_set is not None


class TestTransactionGetUniqueSigners:
    """Tests for Transaction.get_unique_signers() method."""

    def test_can_get_unique_signers_without_inputs(self):
        """Test getting unique signers without resolved inputs."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        signers = transaction.get_unique_signers(None)

        assert signers is not None


class TestTransactionJson:
    """Tests for Transaction JSON serialization."""

    def test_can_serialize_to_json(self):
        """Test serializing transaction to JSON string."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        json_str = transaction.serialize_to_json()

        assert json_str is not None
        assert len(json_str) > 0
        assert '"body"' in json_str

    def test_can_convert_to_dict(self):
        """Test converting transaction to dictionary."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        result = transaction.to_dict()

        assert result is not None
        assert isinstance(result, dict)
        assert "body" in result
        assert "is_valid" in result
        assert "witness_set" in result

    def test_to_cip116_json_with_writer(self):
        """Test serializing to CIP-116 JSON with JsonWriter."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))
        writer = JsonWriter(JsonFormat.COMPACT)

        transaction.to_cip116_json(writer)
        json_str = writer.encode()

        assert json_str is not None
        assert len(json_str) > 0

    def test_to_cip116_json_with_invalid_writer_raises_error(self):
        """Test that invalid writer raises error."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        with pytest.raises(TypeError):
            transaction.to_cip116_json("not a writer")


class TestTransactionRepr:
    """Tests for Transaction.__repr__() method."""

    def test_repr_contains_transaction_id(self):
        """Test that repr includes transaction ID prefix."""
        transaction = Transaction.from_cbor(CborReader.from_hex(CBOR))

        result = repr(transaction)

        assert "Transaction" in result
        assert "id=" in result


class TestTransactionContextManager:
    """Tests for Transaction context manager support."""

    def test_can_use_as_context_manager(self):
        """Test using Transaction in with statement."""
        with Transaction.from_cbor(CborReader.from_hex(CBOR)) as transaction:
            assert transaction is not None
            tx_id = transaction.id
            assert tx_id is not None


class TestTransactionRoundtrip:
    """Tests for Transaction CBOR roundtrip."""

    def test_cbor_roundtrip(self):
        """Test CBOR serialization and deserialization roundtrip."""
        reader = CborReader.from_hex(CBOR)
        tx = Transaction.from_cbor(reader)

        writer = CborWriter()
        tx.to_cbor(writer)
        cbor_hex = writer.to_hex()

        reader2 = CborReader.from_hex(cbor_hex)
        tx2 = Transaction.from_cbor(reader2)

        assert tx2 is not None
        assert tx.id.to_hex() == tx2.id.to_hex()

    def test_multiple_transactions(self):
        """Test parsing multiple different transactions."""
        reader1 = CborReader.from_hex(CBOR)
        tx1 = Transaction.from_cbor(reader1)

        reader2 = CborReader.from_hex(CBOR2)
        tx2 = Transaction.from_cbor(reader2)

        assert tx1 is not None
        assert tx2 is not None
        assert tx1.id.to_hex() != tx2.id.to_hex()
