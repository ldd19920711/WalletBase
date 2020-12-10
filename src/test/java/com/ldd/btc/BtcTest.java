package com.ldd.btc;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.ldd.wallet.Identity;
import com.ldd.wallet.Wallet;
import com.ldd.wallet.WalletManager;
import com.ldd.wallet.keystore.HDMnemonicKeystore;
import com.ldd.wallet.model.BIP44Util;
import com.ldd.wallet.model.ChainId;
import com.ldd.wallet.model.ChainType;
import com.ldd.wallet.model.Metadata;
import com.ldd.wallet.model.Network;
import com.ldd.wallet.transaction.BitcoinTransaction;
import com.ldd.wallet.transaction.BitcoinTransaction.UTXO;
import com.ldd.wallet.transaction.TxSignResult;
import java.io.File;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.bitcoinj.core.Address;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

/**
 * BTC-Wallet相关操作
 *
 * @author ldd
 */
public class BtcTest {

  private final String password = "123456";

  private final String PRIVATE_KEY = "KzkGmbqshdzVrDoFCLzsZiL8zQX5274kq8ANjxe98JzqesqXnhVp";

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
    List<String> mnemonicList = MnemonicCode.INSTANCE.toMnemonic(entropy);
    //使用助记词生成钱包种子
    //可以指定助记词生成钱包
    String mnemonic = String.join(" ", mnemonicList);
    System.out.println("输出助记词: " + mnemonic);
    //普通地址钱包生成逻辑
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_WIF);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager
        .importWalletFromMnemonic(metadata, mnemonic, BIP44Util.BITCOIN_MAINNET_PATH, password,
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
        .importWalletFromMnemonic(metadata, mnemonic, BIP44Util.BITCOIN_SEGWIT_MAIN_PATH, password,
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

  /**
   * 私钥生成BTC钱包
   */
  @Test
  public void test2() throws Exception {
    //普通地址
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_WIF);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager.importWalletFromPrivateKey(metadata,
        PRIVATE_KEY, password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
    //隔离见证地址
    metadata.setSegWit(Metadata.P2WPKH);
    wallet = WalletManager.importWalletFromPrivateKey(metadata,
        PRIVATE_KEY, password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
  }

  /**
   * 根据私钥查询对应钱包(仅支持importWalletFromPrivateKey导入过的钱包)
   */
  @Test
  public void test3() throws Exception {
    //普通地址
    Wallet wallet = WalletManager
        .findWalletByPrivateKey(ChainType.BITCOIN, Network.MAINNET,
            PRIVATE_KEY, null);
    if (wallet == null) {
      return;
    }
    System.out.println(wallet.getId() + "," + wallet.getAddress());
    //隔离见证地址
    wallet = WalletManager
        .findWalletByPrivateKey(ChainType.BITCOIN, Network.MAINNET,
            PRIVATE_KEY, Metadata.P2WPKH);
    if (wallet == null) {
      return;
    }
    System.out.println(wallet.getId() + "," + wallet.getAddress());
    try {
      //删除倒入过的钱包,ID为全局唯一
      WalletManager.removeWallet(wallet.getId(), password);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   * 根据助记词查询该助记词下所有余额(普通地址)
   */
  @Test
  public void test4() throws Exception {
    BigDecimal sum = BigDecimal.ZERO;
    String mnemonic = String
        .join(" ",
            "pluck nice include group expose awkward faint joy tourist sense cinnamon list");
    System.out.println("输出助记词: " + mnemonic);
    //普通地址钱包生成逻辑
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_WIF);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager
        .importWalletFromMnemonic(metadata, mnemonic, BIP44Util.BITCOIN_MAINNET_PATH,
            password,
            true);
    List<String> addressList = new ArrayList<>();
    for (int i = 0; i < 50; i++) {
      addressList.add(wallet.newReceiveAddress(i));
    }
    System.out.println("普通地址余额");
    List<UTXO> utxoList = getUTXOList(String.join(",", addressList), 1);
    for (String addressItem : addressList) {
      Optional<Long> reduce = utxoList.parallelStream().filter(
          u -> u.getAddress().equals(addressItem)
      ).map(BitcoinTransaction.UTXO::getAmount).reduce(Long::sum);
      if (reduce.isPresent()) {
        Long aLong = reduce.get();
        BigDecimal amount = new BigDecimal(aLong)
            .divide(BigDecimal.TEN.pow(8), 8, BigDecimal.ROUND_HALF_UP);
        sum = sum.add(amount);
        System.out.println(
            addressItem + "," + amount
                .stripTrailingZeros());
      }
    }
    addressList.clear();
    for (int i = 0; i < 50; i++) {
      addressList.add(wallet.newReceiveAddress(i, true));
    }
    System.out.println("普通地址(找零)余额");
    utxoList = getUTXOList(String.join(",", addressList), 1);
    for (String addressItem : addressList) {
      Optional<Long> reduce = utxoList.parallelStream().filter(
          u -> u.getAddress().equals(addressItem)
      ).map(BitcoinTransaction.UTXO::getAmount).reduce(Long::sum);
      if (reduce.isPresent()) {
        Long aLong = reduce.get();
        BigDecimal amount = new BigDecimal(aLong)
            .divide(BigDecimal.TEN.pow(8), 8, BigDecimal.ROUND_HALF_UP);
        sum = sum.add(amount);
        System.out.println(
            addressItem + "," + amount
                .stripTrailingZeros());
      }
    }
    System.out.println("普通地址总余额: " + sum.stripTrailingZeros());
  }

  /**
   * 根据助记词查询该助记词下所有余额(隔离见证地址)
   */
  @Test
  public void test5() throws Exception {
    BigDecimal sum = BigDecimal.ZERO;
    String mnemonic = String
        .join(" ",
            "little ketchup cube fruit jump park eight cave kangaroo february weapon broccoli");
    System.out.println("输出助记词: " + mnemonic);
    //普通地址钱包生成逻辑
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_WIF);
    metadata.setSegWit(Metadata.P2WPKH);
    Wallet wallet = WalletManager
        .importWalletFromMnemonic(metadata, mnemonic, BIP44Util.BITCOIN_SEGWIT_MAIN_PATH,
            password,
            true);
    List<String> addressList = new ArrayList<>();
    for (int i = 0; i < 50; i++) {
      addressList.add(wallet.newReceiveAddress(i));
    }
    System.out.println("隔离见证地址余额");
    List<UTXO> utxoList = getUTXOList(String.join(",", addressList), 3);
    for (String addressItem : addressList) {
      Optional<Long> reduce = utxoList.parallelStream().filter(
          u -> u.getAddress().equals(addressItem)
      ).map(BitcoinTransaction.UTXO::getAmount).reduce(Long::sum);
      if (reduce.isPresent()) {
        Long aLong = reduce.get();
        BigDecimal amount = new BigDecimal(aLong)
            .divide(BigDecimal.TEN.pow(8), 8, BigDecimal.ROUND_HALF_UP);
        sum = sum.add(amount);
        System.out.println(
            addressItem + "," + amount
                .stripTrailingZeros());
      }
    }
    addressList.clear();
    for (int i = 0; i < 50; i++) {
      addressList.add(wallet.newReceiveAddress(i, true));
    }
    System.out.println("隔离见证地址(找零)余额");
    utxoList = getUTXOList(String.join(",", addressList), 3);
    for (String addressItem : addressList) {
      Optional<Long> reduce = utxoList.parallelStream().filter(
          u -> u.getAddress().equals(addressItem)
      ).map(BitcoinTransaction.UTXO::getAmount).reduce(Long::sum);
      if (reduce.isPresent()) {
        Long aLong = reduce.get();
        BigDecimal amount = new BigDecimal(aLong)
            .divide(BigDecimal.TEN.pow(8), 8, BigDecimal.ROUND_HALF_UP);
        sum = sum.add(amount);
        System.out.println(
            addressItem + "," + amount
                .stripTrailingZeros());
      }
    }
    System.out.println("隔离见证地址总余额: " + sum.stripTrailingZeros());
  }

  /**
   * 私钥转账(普通地址)
   */
  @Test
  public void test6() throws Exception {
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_WIF);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager.importWalletFromPrivateKey(metadata,
        PRIVATE_KEY,
        password, true);
    List<UTXO> utxoList = getUTXOList(wallet.getAddress(), 1);
    long amount = 1000L;
    BitcoinTransaction bitcoinTransaction = new BitcoinTransaction(
        "", 0, amount, getFee(amount, utxoList), utxoList);
    TxSignResult txSignResult = bitcoinTransaction
        .signTransaction(ChainId.BITCOIN_MAINNET + "", password, wallet);
    String txHash = txSignResult.getTxHash();
    String signedTx = txSignResult.getSignedTx();
    System.out.println(txHash);
    System.out.println(signedTx);
  }

  /**
   * 私钥转账(隔离见证地址)
   */
  @Test
  public void test7() throws Exception {
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.BITCOIN);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_WIF);
    metadata.setSegWit(Metadata.P2WPKH);
    Wallet wallet = WalletManager.importWalletFromPrivateKey(metadata,
        PRIVATE_KEY,
        password, true);
    List<UTXO> utxoList = getUTXOList(wallet.getAddress(), 3);
    long amount = 1000L;
    BitcoinTransaction bitcoinTransaction = new BitcoinTransaction(
        "", 0, amount, getFee(amount, utxoList), utxoList);
    TxSignResult txSignResult = bitcoinTransaction
        .signSegWitTransaction(ChainId.BITCOIN_MAINNET + "", password, wallet);
    String txHash = txSignResult.getTxHash();
    String signedTx = txSignResult.getSignedTx();
    System.out.println(txHash);
    System.out.println(signedTx);
  }

  /**
   * 获取UTXO列表
   *
   * @param walletAddress 地址
   * @param type          类型1普通;2隔离见证
   * @return
   * @throws Exception
   */
  private List<BitcoinTransaction.UTXO> getUTXOList(String walletAddress, int type)
      throws Exception {
    ArrayList<BitcoinTransaction.UTXO> utxoList = new ArrayList<>();
    OkHttpClient client = new OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .build();
    Request request = new Request.Builder()
        .url("https://blockchain.info/unspent?active=" + walletAddress).build();
    Response response = client.newCall(request).execute();
    try {
      ResponseBody body = response.body();
      if (body == null) {
        System.out.println("Error: Body is null");
        return utxoList;
      }
      String bodyString = body.string();
      if ("Invalid Bitcoin Address".equals(bodyString)) {
        System.out.println("Error: Invalid Bitcoin Address");
        return utxoList;
      }
      if ("No free outputs to spend".equals(bodyString)) {
        System.out.println("Error: No free outputs to spend");
        return utxoList;
      }
      JSONObject jsonObject = JSON.parseObject(bodyString);
      JSONArray unspentOutputs = jsonObject.getJSONArray("unspent_outputs");
      for (int i = 0; i < unspentOutputs.size(); i++) {
        JSONObject outputsJSONObject = unspentOutputs.getJSONObject(i);
        String txHash = outputsJSONObject.getString("tx_hash");
        String txHashBigEndian = outputsJSONObject.getString("tx_hash_big_endian");
        Long txOutputN = outputsJSONObject.getLong("tx_output_n");
        String script = outputsJSONObject.getString("script");
        Long value = outputsJSONObject.getLong("value");
        String valueHex = outputsJSONObject.getString("value_hex");
        Long confirmations = outputsJSONObject.getLong("confirmations");
        Long txIndex = outputsJSONObject.getLong("tx_index");
        BitcoinTransaction.UTXO utxo = new BitcoinTransaction.UTXO();
        utxo.setTxHash(txHashBigEndian);
        utxo.setVout(txOutputN.intValue());
        utxo.setAmount(value);
        if (type == 1) {
          String pubKeyHash = String
              .join("", Arrays.asList(script.split("")).subList(6, script.length() - 4));
          Address address = new Address(MainNetParams.get(),
              Hex.decode(pubKeyHash));
          utxo.setAddress(address.toBase58());
        } else {
          String pubKeyHash = String
              .join("", Arrays.asList(script.split("")).subList(4, script.length() - 2));
          String segWitAddress = Address.fromP2SHHash(MainNetParams.get(),
              Hex.decode(pubKeyHash))
              .toBase58();
          utxo.setAddress(segWitAddress);
        }
        utxo.setScriptPubKey(script);
        utxo.setDerivedPath("");
        utxoList.add(utxo);
      }
    } catch (Exception e) {
      String message = e.getMessage();
      System.out.println(message);
    }
    return utxoList;
  }

  /**
   * 计算BTC转账手续费
   *
   * @param amount amount
   * @param utxos  utxos
   * @return 手续费
   */
  public static Long getFee(long amount, List<UTXO> utxos) {
    long feeRate = getFeeRate();//获取费率
    long utxoAmount = 0L;
    long fee = 0L;
    long utxoSize = 0L;
    for (UTXO us : utxos) {
      utxoSize++;
      if (utxoAmount >= (amount + fee)) {
        break;
      } else {
        utxoAmount += us.getAmount();
        fee = (utxoSize * 148 * 34 + 10) * feeRate;
      }
    }
    return fee;
  }

  /**
   * 获取BTC当前费率
   *
   * @return BTC当前费率
   */
  public static Long getFeeRate() {
    try {
      OkHttpClient client = new OkHttpClient.Builder()
          .connectTimeout(10, TimeUnit.SECONDS)
          .readTimeout(20, TimeUnit.SECONDS)
          .build();
      Request request = new Request.Builder()
          .url("https://bitcoinfees.earn.com/api/v1/fees/recommended").build();
      Response response = client.newCall(request).execute();
      String httpGet1 = response.body().string();
      Map map = JSON.parseObject(httpGet1, Map.class);
      return Long.valueOf(map.get("fastestFee").toString());
    } catch (Exception e) {
      e.printStackTrace();
      return 0L;
    }
  }
}
