package com.ldd.trx;

import com.alibaba.fastjson.JSONObject;
import com.ldd.wallet.Identity;
import com.ldd.wallet.Wallet;
import com.ldd.wallet.WalletManager;
import com.ldd.wallet.model.BIP44Util;
import com.ldd.wallet.model.ChainType;
import com.ldd.wallet.model.Metadata;
import com.ldd.wallet.model.Network;
import java.io.File;
import java.security.SecureRandom;
import java.util.List;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.Before;
import org.junit.Test;

/**
 * TRX-Wallet相关操作
 *
 * @author ldd
 */
public class TrxTest {

  private final String password = "123456";

  @Before
  public void before() {
//    try {
//      Files.createDirectories(Paths.get("D:\btchd"));
//    } catch (Throwable ignored) {
//    }
    //KeystoreStorage是接口，实现它的getdir方法
    WalletManager.storage = () -> new File("D:\\btchd");
    Identity identity = Identity.getCurrentIdentity();
    if (identity == null) {
      Identity.createIdentity(
          "token",
          password,
          "",
          Network.MAINNET,
          Metadata.NONE
      );
    }
    WalletManager.scanWallets();
  }

  /**
   * 助记词导入钱包
   */
  @Test
  public void test1() throws Exception {
    SecureRandom secureRandom = new SecureRandom();
    byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
    secureRandom.nextBytes(entropy);
    //生成12位助记词
    List<String> mnemonicList = MnemonicCode.INSTANCE.toMnemonic(entropy);
    //使用助记词生成钱包种子
    //可以指定助记词生成钱包
    String mnemonic = String.join(" ", mnemonicList);
    System.out.println("输出助记词: " + mnemonic);
    //普通地址钱包生成逻辑
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.TRON);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_MNEMONIC);
    Wallet wallet = WalletManager
        .importWalletFromMnemonic(metadata, mnemonic, BIP44Util.TRON_PATH, password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
    System.out.println(JSONObject.toJSONString(wallet.getKeystore()));
  }

  /**
   * 私钥生成钱包
   */
  @Test
  public void test2() {
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.TRON);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_PRIVATE);
    Wallet wallet = WalletManager
        .importWalletFromPrivateKey(metadata,
            "386e00fab25879d6904605c1b3f2f93086ac1563b3699d6a22014099fbe6e8b8", password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
    System.out.println(JSONObject.toJSONString(wallet.getKeystore()));
  }

  /**
   * keystore生成钱包
   */
  @Test
  public void test3() throws Exception {
    //region keystoreContent
    String keystoreContent = "{\n"
        + "    \"address\":\"TFSBecVak43HibvAjnrMcdf3ya3xfntCVY\",\n"
        + "    \"crypto\":{\n"
        + "        \"cipher\":\"aes-128-ctr\",\n"
        + "        \"cipherparams\":{\n"
        + "            \"iv\":\"7a1e99d090c1d94a753dfb6c980cfb8f\"\n"
        + "        },\n"
        + "        \"ciphertext\":\"2a3dd424f23d58774ed5c35be2bdc73912d3f3b97a2aa43f2fd5ffbb3c6c7d7a\",\n"
        + "        \"kdf\":\"pbkdf2\",\n"
        + "        \"kdfparams\":{\n"
        + "            \"c\":10240,\n"
        + "            \"dklen\":32,\n"
        + "            \"prf\":\"hmac-sha256\",\n"
        + "            \"salt\":\"a89f551b247008ef8d790693be8bba4af3badee0a5b0fb4280fc38af562a358d\"\n"
        + "        },\n"
        + "        \"mac\":\"66a0bbb6b8614f36e736343d259cb95f7f0fe7e29d097faff3551808e89c6c84\"\n"
        + "    },\n"
        + "    \"encMnemonic\":{\n"
        + "        \"encStr\":\"5cf7bef5eeca650dfbed6f083006135a64028b4030730297f5d0b0ea4402e844b2a9014b0df9fb4d7bf422b626e135667f2c01028428b29595397eb3cb97134d76e8154e37f75046f5bb1e9b4de69d\",\n"
        + "        \"nonce\":\"69b0738589fead0a68a5be8b62af9e4c\"\n"
        + "    },\n"
        + "    \"id\":\"4785828e-20bb-4402-a785-8edee76b5e24\",\n"
        + "    \"metadata\":{\n"
        + "        \"backup\":[\n"
        + "\n"
        + "        ],\n"
        + "        \"chainType\":\"TRON\",\n"
        + "        \"mainNet\":true,\n"
        + "        \"mode\":\"NORMAL\",\n"
        + "        \"network\":\"MAINNET\",\n"
        + "        \"source\":\"MNEMONIC\",\n"
        + "        \"timestamp\":1607596549,\n"
        + "        \"walletType\":\"V3\"\n"
        + "    },\n"
        + "    \"mnemonicPath\":\"m/44'/195'/0'/0/0\",\n"
        + "    \"version\":3\n"
        + "}";
    //endregion
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.TRON);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_KEYSTORE);
    Wallet wallet = WalletManager
        .importWalletFromKeystore(metadata, keystoreContent, password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
    System.out.println(JSONObject.toJSONString(wallet.getKeystore()));
  }
}
