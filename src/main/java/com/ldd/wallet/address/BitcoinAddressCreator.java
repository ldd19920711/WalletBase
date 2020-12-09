package com.ldd.wallet.address;

import java.util.Arrays;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import com.ldd.foundation.utils.NumericUtil;
import org.spongycastle.util.encoders.Hex;

public class BitcoinAddressCreator implements AddressCreator {
  private NetworkParameters networkParameters;

  public BitcoinAddressCreator(NetworkParameters networkParameters) {
    this.networkParameters = networkParameters;
  }

  @Override
  public String fromPrivateKey(String prvKeyHex) {
    ECKey key;
    if (prvKeyHex.length() == 51 || prvKeyHex.length() == 52) {
      DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(networkParameters, prvKeyHex);
      key = dumpedPrivateKey.getKey();
    } else {
      key = ECKey.fromPrivate(NumericUtil.hexToBytes(prvKeyHex));
    }
    System.out.println("-----"+key.getPublicKeyAsHex());
    byte[] pubKeyHash = key.getPubKeyHash();
    System.out.println("-----"+Hex.toHexString(pubKeyHash));
    System.out.println("-----"+ Arrays.toString(key.getPubKeyPoint().getEncoded()));
    System.out.println("-----"+new Address(this.networkParameters, pubKeyHash).toBase58());
    return new Address(this.networkParameters, pubKeyHash).toBase58();
//    return key.toAddress(this.networkParameters).toBase58();
  }

  @Override
  public String fromPrivateKey(byte[] prvKeyBytes) {
    ECKey key = ECKey.fromPrivate(prvKeyBytes);
    return key.toAddress(this.networkParameters).toBase58();
  }

}
