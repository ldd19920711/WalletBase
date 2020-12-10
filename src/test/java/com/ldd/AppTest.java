package com.ldd;

import com.ldd.wallet.Identity;
import com.ldd.wallet.WalletManager;
import com.ldd.wallet.keystore.IMTKeystore;
import com.ldd.wallet.model.Metadata;
import com.ldd.wallet.model.Network;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest {

  private final String password = "123456";

  @Before
  public void before() {
//    try {
//      Files.createDirectories(Paths.get("${keyStoreProperties.dir}/wallets"));
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
   * 清空当前目录所有已经导入的钱包
   */
  @Test
  public void test1() {
    WalletManager.scanWallets();
    Hashtable<String, IMTKeystore> keyMap = WalletManager.getKeyMap();
    Set<String> strings = keyMap.keySet();
    List<String> list = new ArrayList<>(strings);
    for (String s : list) {
      WalletManager.removeWallet(s, password);
    }
  }
}
