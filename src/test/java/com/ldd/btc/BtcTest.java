package com.ldd.btc;

import com.ldd.wallet.Identity;
import com.ldd.wallet.Wallet;
import com.ldd.wallet.WalletManager;
import com.ldd.wallet.keystore.HDMnemonicKeystore;
import com.ldd.wallet.model.BIP44Util;
import com.ldd.wallet.model.ChainType;
import com.ldd.wallet.model.Metadata;
import com.ldd.wallet.model.Network;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.Before;
import org.junit.Test;

@Slf4j
public class BtcTest {

  private final String password = "123456";

  @Before
  public void before() {
    try {
      Files.createDirectories(Paths.get("${keyStoreProperties.dir}/wallets"));
    } catch (Throwable ignored) {
    }
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
   * 助记词生成BTC钱包 产出普通地址/普通找零地址/隔离见证地址/隔离见证找零/XPUB/私钥 i=0的普通地址path={m/44'/0'/0'/0/0},i递增path={m/44'/0'/0'/0/i}
   * i=0的普通地址(找零)path={m/44'/0'/0'/1/0},i递增path={m/44'/0'/0'/1/i} i=0的普通地址path={m/49'/0'/0'/0/0},i递增path={m/49'/0'/0'/0/i}
   * i=0的普通地址(找零)path={m/49'/0'/0'/1/0},i递增path={m/49'/0'/0'/1/i}
   */
  @Test
  public void test1() throws Exception {
    SecureRandom secureRandom = new SecureRandom();
    byte[] entropy = new byte[DeterministicSeed.DEFAULT_SEED_ENTROPY_BITS / 8];
    secureRandom.nextBytes(entropy);
    //生成12位助记词
    List<String> str = MnemonicCode.INSTANCE.toMnemonic(entropy);
    //使用助记词生成钱包种子
    //可以指定助记词生成钱包
    String collect = String.join(" ", str);
    System.out.println("输出助记词: " + collect);
    //普通地址钱包生成逻辑
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_RECOVERED_IDENTITY);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager
        .importWalletFromMnemonic(metadata, collect, BIP44Util.BITCOIN_MAINNET_PATH, password,
            true);
    System.out.println("输出普通地址:{" + wallet.getAddress() + "}");
    System.out
        .println(
            "输出普通地址对应私钥:{" + WalletManager.bigIntegerToBase58(wallet.exportPrivateKey(password))
                + "}");
    System.out.println("输出xpub:{" + ((HDMnemonicKeystore) (wallet.getKeystore())).getXpub() + "}");
    for (int i = 0; i < 10; i++) {
      System.out
          .printf("输出普通多地址i={%s},address={%s},privateKey={%s}%n", i, wallet.newReceiveAddress(i),
              WalletManager.bigIntegerToBase58(wallet.exportPrivateKey(password, i)));
    }
    for (int i = 0; i < 10; i++) {
      System.out.printf("输出普通多地址(找零)i={%s},address={%s},privateKey={%s}%n", i,
          wallet.newReceiveAddress(i),
          WalletManager.bigIntegerToBase58(wallet.exportPrivateKey(password, i)));
    }
    //隔离见证地址钱包生成逻辑
    metadata.setSegWit(Metadata.P2WPKH);
    wallet = WalletManager
        .importWalletFromMnemonic(metadata, collect, BIP44Util.BITCOIN_SEGWIT_MAIN_PATH, password,
            true);
    System.out.printf("输出隔离见证地址:{%s}%n", wallet.getAddress());
    System.out.printf("输出隔离见证地址对应私钥:{%s}%n",
        WalletManager.bigIntegerToBase58(wallet.exportPrivateKey(password)));
    System.out.printf("输出xpub:{%s}%n", ((HDMnemonicKeystore) (wallet.getKeystore())).getXpub());
    for (int i = 0; i < 10; i++) {
      System.out
          .printf("输出隔离见证多地址i={%s},address={%s},privateKey={%s}%n", i, wallet.newReceiveAddress(i),
              WalletManager.bigIntegerToBase58(wallet.exportPrivateKey(password, i)));
    }
    for (int i = 0; i < 10; i++) {
      System.out.printf("输出隔离见证多地址(找零)i={%s},address={%s},privateKey={%s}%n", i,
          wallet.newReceiveAddress(i),
          WalletManager.bigIntegerToBase58(wallet.exportPrivateKey(password, i)));
    }
  }


}
