package com.ldd.eth;

import com.alibaba.fastjson.JSONObject;
import com.ldd.wallet.Identity;
import com.ldd.wallet.Wallet;
import com.ldd.wallet.WalletManager;
import com.ldd.wallet.model.BIP44Util;
import com.ldd.wallet.model.ChainType;
import com.ldd.wallet.model.Metadata;
import com.ldd.wallet.model.Network;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.wallet.DeterministicSeed;
import org.junit.Before;
import org.junit.Test;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Response;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Convert.Unit;
import org.web3j.utils.Numeric;

/**
 * ETH-Wallet相关操作
 *
 * @author ldd
 */
public class EthTest {

  private final String password = "123456";
  /**
   * 主网节点
   */
  private static final String MAIN_NODE_URL = "https://mainnet.infura.io/v3/ea23a1df0c16486ab0dd0f48a6566f4c";
  /**
   * ROPSTEN测试网节点
   */
  private static final String ROPSTEN_NODE_URL = "https://ropsten.infura.io/v3/ea23a1df0c16486ab0dd0f48a6566f4c";

  private Web3j mainWeb3j;

  private Web3j ropstenWeb3j;

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

    mainWeb3j = Web3j
        .build(new HttpService(MAIN_NODE_URL));
    ropstenWeb3j = Web3j
        .build(new HttpService(ROPSTEN_NODE_URL));

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
    metadata.setChainType(ChainType.ETHEREUM);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_MNEMONIC);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager
        .importWalletFromMnemonic(metadata, mnemonic, BIP44Util.ETHEREUM_PATH, password, true);
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
    metadata.setChainType(ChainType.ETHEREUM);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_PRIVATE);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager
        .importWalletFromPrivateKey(metadata,
            "40185c699b5f7b5231d3e973848f1e8badb2055f2aff89d42979ebb14050eaa1", password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
    System.out.println(JSONObject.toJSONString(wallet.getKeystore()));
  }

  /**
   * keystore生成钱包
   */
  @Test
  public void test3() throws Exception{
    //region keystoreContent
    String keystoreContent = "{\n"
        + "    \"address\":\"0b180b56aa7c8cfa74d076a606c0c6ee4c9c7362\",\n"
        + "    \"crypto\":{\n"
        + "        \"cipher\":\"aes-128-ctr\",\n"
        + "        \"cipherparams\":{\n"
        + "            \"iv\":\"657a1b2086769f6d152f17ea8da9161d\"\n"
        + "        },\n"
        + "        \"ciphertext\":\"67c632f62dba2775cb6fbbc2e0ca5228d2fd0d1f3c38fb5c4a44554adb34daee\",\n"
        + "        \"kdf\":\"pbkdf2\",\n"
        + "        \"kdfparams\":{\n"
        + "            \"c\":10240,\n"
        + "            \"dklen\":32,\n"
        + "            \"prf\":\"hmac-sha256\",\n"
        + "            \"salt\":\"bf257b5ca2e26ec4fd44b8434a463cc5818fae3eb9a3d0e0665a3d7da225581d\"\n"
        + "        },\n"
        + "        \"mac\":\"55ef2a2c74cced90a67603a3ccb60b0a00d050931f2fa037f7e5b4346b6a393d\"\n"
        + "    },\n"
        + "    \"id\":\"dd35b84d-924a-4a9e-811f-c967ae25252b\",\n"
        + "    \"metadata\":{\n"
        + "        \"backup\":[\n"
        + "\n"
        + "        ],\n"
        + "        \"chainType\":\"ETHEREUM\",\n"
        + "        \"mainNet\":true,\n"
        + "        \"mode\":\"NORMAL\",\n"
        + "        \"network\":\"MAINNET\",\n"
        + "        \"segWit\":\"NONE\",\n"
        + "        \"source\":\"PRIVATE\",\n"
        + "        \"timestamp\":0,\n"
        + "        \"walletType\":\"V3\"\n"
        + "    },\n"
        + "    \"version\":3\n"
        + "}";
    //endregion
    Metadata metadata = new Metadata();
    metadata.setChainType(ChainType.ETHEREUM);
    metadata.setNetwork(Network.MAINNET);
    metadata.setSource(Metadata.FROM_KEYSTORE);
    metadata.setSegWit(Metadata.NONE);
    Wallet wallet = WalletManager
        .importWalletFromKeystore(metadata, keystoreContent, password, true);
    System.out.println(wallet.getAddress());
    System.out.println(wallet.exportPrivateKey(password));
    System.out.println(JSONObject.toJSONString(wallet.getKeystore()));
  }

  /**
   * 1.查询代币精度; 2.查询代币余额
   */
  @Test
  public void test4() throws Exception {
    String contractAddress = "0xF8cf6e96651985978aB869e2DfeE3f165f9494Df";
    String accountAddress = "0xcC151a0544f87F8c9c5DBd8713aE3ebd8a1e813C";
    String tokenDecimals = getTokenDecimals(contractAddress,
        accountAddress, ropstenWeb3j);
    System.out.println("合约地址对应代币精度: " + tokenDecimals);
    BigDecimal tokenBalance = getTokenBalance(accountAddress,
        contractAddress, ropstenWeb3j);
    System.out.println("账户下对应合约地址代币余额: " + tokenBalance.divide(
        new BigDecimal(10).pow(Integer.parseInt(tokenDecimals)),
        Integer.parseInt(tokenDecimals),
        BigDecimal.ROUND_HALF_UP
    ).stripTrailingZeros().toPlainString());
  }

  /**
   * 查询ETH余额
   */
  @Test
  public void test5() throws Exception {
    String address = "0xcC151a0544f87F8c9c5DBd8713aE3ebd8a1e813C";
    EthGetBalance send = ropstenWeb3j.ethGetBalance(address, DefaultBlockParameterName.LATEST)
        .send();
    System.out
        .println(Convert.fromWei(BigDecimal.valueOf(send.getBalance().longValue()), Unit.ETHER));
  }

  /**
   * eth转账
   */
  @Test
  public void test6() {
    BigDecimal amount = new BigDecimal("0.001");
    String toAddress = "";
    String privateKey = "";
    String txHash = transferEth(amount, toAddress, privateKey, mainWeb3j);
    System.out.println("txHash: " + txHash);
  }

  /**
   * eth转账(离线签名)
   */
  @Test
  public void test7() throws Exception {
    BigDecimal amount = new BigDecimal("0.001");
    String toAddress = "";
    String privateKey = "";
    String txHash = transferEthOffline(amount, toAddress, privateKey, mainWeb3j);
    System.out.println("txHash: " + txHash);
  }

  /**
   * ERC20转账(离线签名)
   */
  @Test
  public void test8() throws Exception {
    BigInteger amount = BigInteger.valueOf(10000L);
    String accountAddress = "";
    String toAddress = "";
    String privateKey = "";
    String contractAddress = "";
    String tokenDecimals = getTokenDecimals(contractAddress,
        accountAddress, ropstenWeb3j);
    String txHash = transferTokenOffline(amount, toAddress, privateKey, contractAddress,
        tokenDecimals, mainWeb3j);
    System.out.println("txHash: " + txHash);
  }

  /**
   * eth转账
   *
   * @param num        num
   * @param toAddress  toAddress
   * @param privateKey privateKey
   * @param web3j      web3j
   * @return txHash
   */
  public String transferEth(BigDecimal num, String toAddress, String privateKey, Web3j web3j) {
    try {
      Credentials credentials = Credentials.create(privateKey);
      TransactionReceipt transferReceipt = Transfer
          .sendFunds(web3j, credentials, toAddress, num, Convert.Unit.ETHER).send();
      String txHash = transferReceipt.getTransactionHash();
      System.out.println(
          "转出eth数量：" + num + ",转出地址：" + credentials.getAddress() + ",转入项目方地址：" + toAddress
              + "，txHash:"
              + txHash);
      return txHash;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }


  /**
   * ETH离线签名并广播
   *
   * @param num        num
   * @param toAddress  toAddress
   * @param privateKey privateKey
   * @param web3j      web3j
   * @return txHash
   */
  public String transferEthOffline(BigDecimal num, String toAddress, String privateKey, Web3j web3j)
      throws Exception {
    String txHash;
    Credentials credentials = Credentials.create(privateKey);
    BigInteger nonce = getNonce(credentials.getAddress(), web3j);
    BigInteger gasPrice = getGasPrice(web3j);
    //gasLimit默认21000,可以根据实际需求修改
    BigInteger gasLimit = BigInteger.valueOf(21000L);
    BigDecimal realNum = num.multiply(BigDecimal.valueOf(Math.pow(10, 18)));
    BigInteger value = realNum.toBigInteger();
    RawTransaction rawTransaction = RawTransaction
        .createEtherTransaction(nonce, gasPrice, gasLimit, toAddress, value);
    byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
    String hexValue = Numeric.toHexString(signedMessage);
    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();
    Response.Error error = ethSendTransaction.getError();
    if (null != error) {
      throw new Exception("发送交易失败！");
    }
    txHash = ethSendTransaction.getTransactionHash();
    System.out.println("转出token数量：" + num + "，txHash:" + txHash);
    return txHash;
  }

  /**
   * trc20代币离线签名并广播
   *
   * @param toAddress       toAddress
   * @param num             num
   * @param privateKey      privateKey
   * @param contractAddress token合约地址
   * @param decimals        token精度
   * @param web3j           web3j
   * @return txHash
   */
  public String transferTokenOffline(BigInteger num, String toAddress, String privateKey,
      String contractAddress, String decimals, Web3j web3j) throws Exception {
    String txHash;
    Credentials credentials = Credentials.create(privateKey);
    BigInteger nonce = getNonce(credentials.getAddress(), web3j);
    num = switchNum(decimals, num);
    Function function = new Function("transfer",
        Arrays.asList(new Address(toAddress), new Uint256(num)),
        Collections
            .emptyList());
    String data = FunctionEncoder.encode(function);
    BigInteger gasPrice = getGasPrice(web3j);
    BigInteger gasLimit;
    try {
      gasLimit = getGasLimit(credentials.getAddress(), nonce, gasPrice, null, contractAddress,
          data, web3j);
    } catch (Exception e) {
      //如果取不到则用默认值,可以根据实际需求修改
      gasLimit = BigInteger.valueOf(60000L);
    }
    RawTransaction rawTransaction = RawTransaction
        .createTransaction(nonce, gasPrice, gasLimit, contractAddress, data);
    byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
    String hexValue = Numeric.toHexString(signedMessage);
    EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();
    txHash = ethSendTransaction.getTransactionHash();
    return txHash;
  }

  /**
   * 根据精度转化num
   *
   * @param decimals 精度
   * @param num      num
   * @return 转换后结果
   */
  public static BigInteger switchNum(String decimals, BigInteger num) {
    double added = Math.pow(10, Double.parseDouble(decimals));
    num = num.multiply(new BigInteger(String.valueOf(new BigDecimal(added))));
    return num;
  }

  /**
   * 获取gasPrice
   *
   * @return gasPrice
   */
  public BigInteger getGasPrice(Web3j web3j) throws Exception {
    return web3j.ethGasPrice().send().getGasPrice();
  }

  /**
   * 获取gasLimit
   *
   * @param accountAddress  accountAddress
   * @param nonce           nonce
   * @param gasPrice        gasPrice
   * @param gasLimit        gasLimit
   * @param contractAddress token合约地址
   * @param data            交易数据(toHex)
   * @return gasLimit
   */
  public BigInteger getGasLimit(String accountAddress, BigInteger nonce, BigInteger gasPrice,
      BigInteger gasLimit, String contractAddress, String data, Web3j web3j) throws Exception {
    Transaction transaction = Transaction.createFunctionCallTransaction(
        accountAddress, nonce, gasPrice, gasLimit, contractAddress, data);
    EthEstimateGas ethEstimateGas = web3j.ethEstimateGas(transaction).send();
    return ethEstimateGas.getAmountUsed();
  }

  /**
   * 查询nonce值
   *
   * @param address address
   * @param web3j   web3j
   * @return nonce值
   */
  public BigInteger getNonce(String address, Web3j web3j) {
    try {
      EthGetTransactionCount ethGetTransactionCount = web3j
          .ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).send();
      if (null == ethGetTransactionCount || ethGetTransactionCount.hasError()) {
        System.out
            .println("get nonce return error: " + ethGetTransactionCount.getError().getMessage());
      }
      return ethGetTransactionCount.getTransactionCount();
    } catch (IOException e) {
      System.out.println("get nonce time out error, address: " + address);
      return null;
    }
  }

  /**
   * 查询token精度
   *
   * @param contractAddress contractAddress
   * @param accountAddress  accountAddress
   */

  public String getTokenDecimals(String contractAddress, String accountAddress, Web3j web3j) {
    try {
      Function function = new Function("decimals", Collections.emptyList(),
          Arrays.asList(new TypeReference<Uint256>() {
          }));
      return getTokenVariable(contractAddress, accountAddress, function, web3j);
    } catch (Exception e) {
      e.printStackTrace();
      return "";
    }
  }

  /**
   * 查询token余额
   *
   * @param fromAddress     指定地址
   * @param contractAddress token合约地址
   */

  public BigDecimal getTokenBalance(String fromAddress, String contractAddress, Web3j web3j) {
    String methodName = "balanceOf";
    List<Type> inputParameters = new ArrayList<>();
    List<TypeReference<?>> outputParameters = new ArrayList<>();
    try {
      Address address = new Address(fromAddress);
      inputParameters.add(address);
    } catch (Exception ex) {
      return new BigDecimal(0);
    }
    TypeReference<Uint256> typeReference = new TypeReference<Uint256>() {
    };
    outputParameters.add(typeReference);
    Function function = new Function(methodName, inputParameters, outputParameters);
    String data = FunctionEncoder.encode(function);
    Transaction transaction = Transaction
        .createEthCallTransaction(fromAddress, contractAddress, data);
    EthCall ethCall;
    BigInteger balanceValue = BigInteger.ZERO;
    try {
      ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).send();
      List<Type> results = FunctionReturnDecoder
          .decode(ethCall.getValue(), function.getOutputParameters());
      if (!results.isEmpty()) {
        balanceValue = (BigInteger) results.get(0).getValue();
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
    return Convert.fromWei(new BigDecimal(balanceValue), Unit.WEI);
  }

  /**
   * 根据functionName查询对应值
   *
   * @param contractAddress contractAddress
   * @param accountAddress  accountAddress
   * @param function        function
   * @param web3j           web3j
   */
  public String getTokenVariable(String contractAddress, String accountAddress, Function function,
      Web3j web3j) {
    try {
      String encodedFunction = FunctionEncoder.encode(function);
      Transaction transaction = Transaction.createEthCallTransaction(accountAddress,
          contractAddress, encodedFunction);
      EthCall response = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync()
          .get();
      List<Type> resultTypes = FunctionReturnDecoder.decode(
          response.getValue(), function.getOutputParameters());
      return resultTypes.get(0).getValue().toString();
    } catch (Exception e) {
      return "";
    }
  }

}
