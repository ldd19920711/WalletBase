package com.ldd.wallet.address;

import java.util.Arrays;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.DumpedPrivateKey;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import com.ldd.foundation.utils.NumericUtil;
import com.ldd.wallet.model.Messages;
import com.ldd.wallet.model.TokenException;
import org.spongycastle.util.encoders.Hex;

public class SegWitBitcoinAddressCreator implements AddressCreator {
  private NetworkParameters networkParameters;

  public SegWitBitcoinAddressCreator(NetworkParameters networkParameters) {
    this.networkParameters = networkParameters;
  }

  @Override
  public String fromPrivateKey(String prvKeyHex) {
    ECKey key;
    if (prvKeyHex.length() == 51 || prvKeyHex.length() == 52) {
      DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(networkParameters, prvKeyHex);
      key = dumpedPrivateKey.getKey();
      if (!key.isCompressed()) {
        throw new TokenException(Messages.SEGWIT_NEEDS_COMPRESS_PUBLIC_KEY);
      }
    } else {
      key = ECKey.fromPrivate(NumericUtil.hexToBytes(prvKeyHex), true);
    }
    return calcSegWitAddress(key.getPubKeyHash());
  }

  @Override
  public String fromPrivateKey(byte[] prvKeyBytes) {
    ECKey key = ECKey.fromPrivate(prvKeyBytes, true);
    return calcSegWitAddress(key.getPubKeyHash());
  }

  private String calcSegWitAddress(byte[] pubKeyHash) {
    String redeemScript = String.format("0x0014%s", NumericUtil.bytesToHex(pubKeyHash));
    return Address.fromP2SHHash(networkParameters, Utils.sha256hash160(NumericUtil.hexToBytes(redeemScript))).toBase58();
  }

  public Address fromPrivateKey(ECKey ecKey) {
    String redeemScript = String.format("0x0014%s", NumericUtil.bytesToHex(ecKey.getPubKeyHash()));
    return Address.fromP2SHHash(networkParameters, Utils.sha256hash160(NumericUtil.hexToBytes(redeemScript)));
  }

}
