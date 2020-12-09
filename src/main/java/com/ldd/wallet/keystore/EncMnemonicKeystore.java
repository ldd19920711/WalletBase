package com.ldd.wallet.keystore;

import com.ldd.foundation.crypto.Crypto;
import com.ldd.foundation.crypto.EncPair;
import java.nio.charset.Charset;

public interface EncMnemonicKeystore {

  EncPair getEncMnemonic();

  void setEncMnemonic(EncPair encMnemonic);

  String getMnemonicPath();

  Crypto getCrypto();

  default void createEncMnemonic(String password, String mnemonic) {
    EncPair encMnemonic = getCrypto()
        .deriveEncPair(password, mnemonic.getBytes(Charset.forName("UTF-8")));
    this.setEncMnemonic(encMnemonic);
  }

  default String decryptMnemonic(String password) {
    return new String(getCrypto().decryptEncPair(password, getEncMnemonic()));
  }


}
