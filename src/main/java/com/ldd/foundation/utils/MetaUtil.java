package com.ldd.foundation.utils;

import com.ldd.wallet.model.ChainType;
import com.ldd.wallet.model.Metadata;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;

/**
 * Created by pie on 2018/12/5 15: 32.
 */
public class MetaUtil {

  public static NetworkParameters getNetWork(Metadata metadata) {
    NetworkParameters network = null;
    if (metadata.getChainType() == null) {
      return MainNetParams.get();
    }
    switch (metadata.getChainType()) {
      case ChainType.BITCOIN:
        network = metadata.isMainNet() ? MainNetParams.get() : TestNet3Params.get();
        break;
      default:
        break;
    }
    return network;
  }
}
